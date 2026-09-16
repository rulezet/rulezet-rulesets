rule TTP_XOR_WriteProcessMemory_e154 {
  strings:
    $key_e154 = { b6 26 [2] 84 04 [2] 82 31 [2] ac 31 [2] 93 2d }

  condition:
    any of them
}