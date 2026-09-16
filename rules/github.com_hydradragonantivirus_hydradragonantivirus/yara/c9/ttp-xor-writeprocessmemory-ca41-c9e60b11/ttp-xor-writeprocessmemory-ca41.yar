rule TTP_XOR_WriteProcessMemory_ca41 {
  strings:
    $key_ca41 = { 9d 33 [2] af 11 [2] a9 24 [2] 87 24 [2] b8 38 }

  condition:
    any of them
}