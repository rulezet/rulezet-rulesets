rule TTP_XOR_WriteProcessMemory_e250 {
  strings:
    $key_e250 = { b5 22 [2] 87 00 [2] 81 35 [2] af 35 [2] 90 29 }

  condition:
    any of them
}