rule TTP_XOR_WriteProcessMemory_e1b3 {
  strings:
    $key_e1b3 = { b6 c1 [2] 84 e3 [2] 82 d6 [2] ac d6 [2] 93 ca }

  condition:
    any of them
}