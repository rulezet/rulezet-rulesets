rule TTP_XOR_WriteProcessMemory_dc63 {
  strings:
    $key_dc63 = { 8b 11 [2] b9 33 [2] bf 06 [2] 91 06 [2] ae 1a }

  condition:
    any of them
}