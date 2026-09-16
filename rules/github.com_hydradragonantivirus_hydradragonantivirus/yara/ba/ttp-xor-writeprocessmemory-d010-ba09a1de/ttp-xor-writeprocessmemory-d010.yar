rule TTP_XOR_WriteProcessMemory_d010 {
  strings:
    $key_d010 = { 87 62 [2] b5 40 [2] b3 75 [2] 9d 75 [2] a2 69 }

  condition:
    any of them
}