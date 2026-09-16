rule TTP_XOR_WriteProcessMemory_6868 {
  strings:
    $key_6868 = { 3f 1a [2] 0d 38 [2] 0b 0d [2] 25 0d [2] 1a 11 }

  condition:
    any of them
}