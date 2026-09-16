rule TTP_XOR_WriteProcessMemory_ca00 {
  strings:
    $key_ca00 = { 9d 72 [2] af 50 [2] a9 65 [2] 87 65 [2] b8 79 }

  condition:
    any of them
}