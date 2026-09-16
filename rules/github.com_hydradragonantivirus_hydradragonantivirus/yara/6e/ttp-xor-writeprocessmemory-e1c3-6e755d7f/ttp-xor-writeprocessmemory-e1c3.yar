rule TTP_XOR_WriteProcessMemory_e1c3 {
  strings:
    $key_e1c3 = { b6 b1 [2] 84 93 [2] 82 a6 [2] ac a6 [2] 93 ba }

  condition:
    any of them
}