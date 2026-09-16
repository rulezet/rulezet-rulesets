rule TTP_XOR_WriteProcessMemory_ca31 {
  strings:
    $key_ca31 = { 9d 43 [2] af 61 [2] a9 54 [2] 87 54 [2] b8 48 }

  condition:
    any of them
}