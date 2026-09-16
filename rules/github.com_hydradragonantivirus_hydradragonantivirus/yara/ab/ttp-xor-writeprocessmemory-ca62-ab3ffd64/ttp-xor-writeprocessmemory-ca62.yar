rule TTP_XOR_WriteProcessMemory_ca62 {
  strings:
    $key_ca62 = { 9d 10 [2] af 32 [2] a9 07 [2] 87 07 [2] b8 1b }

  condition:
    any of them
}