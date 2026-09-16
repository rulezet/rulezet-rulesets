rule TTP_XOR_WriteProcessMemory_c9e8 {
  strings:
    $key_c9e8 = { 9e 9a [2] ac b8 [2] aa 8d [2] 84 8d [2] bb 91 }

  condition:
    any of them
}