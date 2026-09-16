rule TTP_XOR_WriteProcessMemory_dcf0 {
  strings:
    $key_dcf0 = { 8b 82 [2] b9 a0 [2] bf 95 [2] 91 95 [2] ae 89 }

  condition:
    any of them
}