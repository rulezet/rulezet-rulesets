rule TTP_XOR_WriteProcessMemory_ca65 {
  strings:
    $key_ca65 = { 9d 17 [2] af 35 [2] a9 00 [2] 87 00 [2] b8 1c }

  condition:
    any of them
}