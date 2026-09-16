rule TTP_XOR_WriteProcessMemory_caf3 {
  strings:
    $key_caf3 = { 9d 81 [2] af a3 [2] a9 96 [2] 87 96 [2] b8 8a }

  condition:
    any of them
}