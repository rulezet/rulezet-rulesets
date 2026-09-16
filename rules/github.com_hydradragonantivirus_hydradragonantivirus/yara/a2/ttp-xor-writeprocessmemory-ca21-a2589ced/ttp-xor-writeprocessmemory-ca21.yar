rule TTP_XOR_WriteProcessMemory_ca21 {
  strings:
    $key_ca21 = { 9d 53 [2] af 71 [2] a9 44 [2] 87 44 [2] b8 58 }

  condition:
    any of them
}