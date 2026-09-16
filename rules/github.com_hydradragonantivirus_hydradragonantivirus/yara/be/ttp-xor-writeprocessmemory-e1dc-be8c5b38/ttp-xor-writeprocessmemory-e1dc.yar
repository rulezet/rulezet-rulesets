rule TTP_XOR_WriteProcessMemory_e1dc {
  strings:
    $key_e1dc = { b6 ae [2] 84 8c [2] 82 b9 [2] ac b9 [2] 93 a5 }

  condition:
    any of them
}