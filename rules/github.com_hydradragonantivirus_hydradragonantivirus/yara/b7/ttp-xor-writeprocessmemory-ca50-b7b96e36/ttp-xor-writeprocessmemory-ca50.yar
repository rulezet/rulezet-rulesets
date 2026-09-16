rule TTP_XOR_WriteProcessMemory_ca50 {
  strings:
    $key_ca50 = { 9d 22 [2] af 00 [2] a9 35 [2] 87 35 [2] b8 29 }

  condition:
    any of them
}