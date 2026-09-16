rule TTP_XOR_WriteProcessMemory_ca32 {
  strings:
    $key_ca32 = { 9d 40 [2] af 62 [2] a9 57 [2] 87 57 [2] b8 4b }

  condition:
    any of them
}