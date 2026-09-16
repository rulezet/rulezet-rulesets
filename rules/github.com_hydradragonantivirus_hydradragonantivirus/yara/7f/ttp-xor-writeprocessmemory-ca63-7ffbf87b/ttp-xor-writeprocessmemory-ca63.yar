rule TTP_XOR_WriteProcessMemory_ca63 {
  strings:
    $key_ca63 = { 9d 11 [2] af 33 [2] a9 06 [2] 87 06 [2] b8 1a }

  condition:
    any of them
}