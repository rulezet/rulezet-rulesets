rule TTP_XOR_WriteProcessMemory_d0f8 {
  strings:
    $key_d0f8 = { 87 8a [2] b5 a8 [2] b3 9d [2] 9d 9d [2] a2 81 }

  condition:
    any of them
}