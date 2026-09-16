rule TTP_XOR_WriteProcessMemory_c908 {
  strings:
    $key_c908 = { 9e 7a [2] ac 58 [2] aa 6d [2] 84 6d [2] bb 71 }

  condition:
    any of them
}