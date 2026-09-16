rule TTP_XOR_WriteProcessMemory_2f08 {
  strings:
    $key_2f08 = { 78 7a [2] 4a 58 [2] 4c 6d [2] 62 6d [2] 5d 71 }

  condition:
    any of them
}