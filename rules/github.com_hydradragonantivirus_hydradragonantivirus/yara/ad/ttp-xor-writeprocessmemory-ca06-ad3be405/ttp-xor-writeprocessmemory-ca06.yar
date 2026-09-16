rule TTP_XOR_WriteProcessMemory_ca06 {
  strings:
    $key_ca06 = { 9d 74 [2] af 56 [2] a9 63 [2] 87 63 [2] b8 7f }

  condition:
    any of them
}