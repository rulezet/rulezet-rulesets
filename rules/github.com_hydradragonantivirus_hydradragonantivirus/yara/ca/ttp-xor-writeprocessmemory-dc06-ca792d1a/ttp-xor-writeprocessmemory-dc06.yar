rule TTP_XOR_WriteProcessMemory_dc06 {
  strings:
    $key_dc06 = { 8b 74 [2] b9 56 [2] bf 63 [2] 91 63 [2] ae 7f }

  condition:
    any of them
}