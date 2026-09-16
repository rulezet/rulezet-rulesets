rule TTP_XOR_WriteProcessMemory_dc26 {
  strings:
    $key_dc26 = { 8b 54 [2] b9 76 [2] bf 43 [2] 91 43 [2] ae 5f }

  condition:
    any of them
}