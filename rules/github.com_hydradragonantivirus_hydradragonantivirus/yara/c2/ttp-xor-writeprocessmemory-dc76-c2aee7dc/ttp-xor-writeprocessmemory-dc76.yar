rule TTP_XOR_WriteProcessMemory_dc76 {
  strings:
    $key_dc76 = { 8b 04 [2] b9 26 [2] bf 13 [2] 91 13 [2] ae 0f }

  condition:
    any of them
}