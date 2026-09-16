rule TTP_XOR_WriteProcessMemory_dc61 {
  strings:
    $key_dc61 = { 8b 13 [2] b9 31 [2] bf 04 [2] 91 04 [2] ae 18 }

  condition:
    any of them
}