rule TTP_XOR_WriteProcessMemory_3868 {
  strings:
    $key_3868 = { 6f 1a [2] 5d 38 [2] 5b 0d [2] 75 0d [2] 4a 11 }

  condition:
    any of them
}