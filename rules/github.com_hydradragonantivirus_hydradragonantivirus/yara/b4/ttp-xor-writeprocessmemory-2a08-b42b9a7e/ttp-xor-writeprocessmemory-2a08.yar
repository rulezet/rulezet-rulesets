rule TTP_XOR_WriteProcessMemory_2a08 {
  strings:
    $key_2a08 = { 7d 7a [2] 4f 58 [2] 49 6d [2] 67 6d [2] 58 71 }

  condition:
    any of them
}