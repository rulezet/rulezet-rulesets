rule TTP_XOR_WriteProcessMemory_c918 {
  strings:
    $key_c918 = { 9e 6a [2] ac 48 [2] aa 7d [2] 84 7d [2] bb 61 }

  condition:
    any of them
}