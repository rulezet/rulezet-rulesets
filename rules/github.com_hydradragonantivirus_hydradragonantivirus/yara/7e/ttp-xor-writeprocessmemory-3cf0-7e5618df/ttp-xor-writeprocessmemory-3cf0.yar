rule TTP_XOR_WriteProcessMemory_3cf0 {
  strings:
    $key_3cf0 = { 6b 82 [2] 59 a0 [2] 5f 95 [2] 71 95 [2] 4e 89 }

  condition:
    any of them
}