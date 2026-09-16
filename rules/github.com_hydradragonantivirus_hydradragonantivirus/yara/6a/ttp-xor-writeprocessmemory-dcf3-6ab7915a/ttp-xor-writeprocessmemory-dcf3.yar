rule TTP_XOR_WriteProcessMemory_dcf3 {
  strings:
    $key_dcf3 = { 8b 81 [2] b9 a3 [2] bf 96 [2] 91 96 [2] ae 8a }

  condition:
    any of them
}