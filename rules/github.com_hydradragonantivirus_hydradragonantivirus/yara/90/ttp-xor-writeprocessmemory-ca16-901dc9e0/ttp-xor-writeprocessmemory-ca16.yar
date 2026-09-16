rule TTP_XOR_WriteProcessMemory_ca16 {
  strings:
    $key_ca16 = { 9d 64 [2] af 46 [2] a9 73 [2] 87 73 [2] b8 6f }

  condition:
    any of them
}