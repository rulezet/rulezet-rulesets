rule TTP_XOR_WriteProcessMemory_d008 {
  strings:
    $key_d008 = { 87 7a [2] b5 58 [2] b3 6d [2] 9d 6d [2] a2 71 }

  condition:
    any of them
}