rule TTP_XOR_WriteProcessMemory_5038 {
  strings:
    $key_5038 = { 07 4a [2] 35 68 [2] 33 5d [2] 1d 5d [2] 22 41 }

  condition:
    any of them
}