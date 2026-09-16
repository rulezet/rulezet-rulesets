rule TTP_XOR_WriteProcessMemory_caf0 {
  strings:
    $key_caf0 = { 9d 82 [2] af a0 [2] a9 95 [2] 87 95 [2] b8 89 }

  condition:
    any of them
}