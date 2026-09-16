rule TTP_XOR_WriteProcessMemory_ca66 {
  strings:
    $key_ca66 = { 9d 14 [2] af 36 [2] a9 03 [2] 87 03 [2] b8 1f }

  condition:
    any of them
}