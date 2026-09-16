rule TTP_XOR_WriteProcessMemory_3908 {
  strings:
    $key_3908 = { 6e 7a [2] 5c 58 [2] 5a 6d [2] 74 6d [2] 4b 71 }

  condition:
    any of them
}