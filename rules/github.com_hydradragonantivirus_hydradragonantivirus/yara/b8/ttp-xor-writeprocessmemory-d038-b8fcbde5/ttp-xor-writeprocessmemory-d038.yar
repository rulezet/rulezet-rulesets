rule TTP_XOR_WriteProcessMemory_d038 {
  strings:
    $key_d038 = { 87 4a [2] b5 68 [2] b3 5d [2] 9d 5d [2] a2 41 }

  condition:
    any of them
}