rule TTP_XOR_WriteProcessMemory_dc65 {
  strings:
    $key_dc65 = { 8b 17 [2] b9 35 [2] bf 00 [2] 91 00 [2] ae 1c }

  condition:
    any of them
}