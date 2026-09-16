rule TTP_XOR_WriteProcessMemory_e1f4 {
  strings:
    $key_e1f4 = { b6 86 [2] 84 a4 [2] 82 91 [2] ac 91 [2] 93 8d }

  condition:
    any of them
}