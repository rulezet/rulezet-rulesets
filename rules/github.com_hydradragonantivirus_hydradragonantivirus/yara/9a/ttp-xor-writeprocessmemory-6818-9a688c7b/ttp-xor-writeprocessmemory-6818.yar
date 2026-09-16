rule TTP_XOR_WriteProcessMemory_6818 {
  strings:
    $key_6818 = { 3f 6a [2] 0d 48 [2] 0b 7d [2] 25 7d [2] 1a 61 }

  condition:
    any of them
}