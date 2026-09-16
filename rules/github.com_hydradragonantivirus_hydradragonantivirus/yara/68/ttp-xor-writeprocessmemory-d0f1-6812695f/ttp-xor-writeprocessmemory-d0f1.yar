rule TTP_XOR_WriteProcessMemory_d0f1 {
  strings:
    $key_d0f1 = { 87 83 [2] b5 a1 [2] b3 94 [2] 9d 94 [2] a2 88 }

  condition:
    any of them
}