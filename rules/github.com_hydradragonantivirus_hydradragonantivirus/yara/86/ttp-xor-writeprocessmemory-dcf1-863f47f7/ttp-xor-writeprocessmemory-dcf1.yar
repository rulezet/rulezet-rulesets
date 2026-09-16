rule TTP_XOR_WriteProcessMemory_dcf1 {
  strings:
    $key_dcf1 = { 8b 83 [2] b9 a1 [2] bf 94 [2] 91 94 [2] ae 88 }

  condition:
    any of them
}