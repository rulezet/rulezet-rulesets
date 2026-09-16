rule TTP_XOR_WriteProcessMemory_ca74 {
  strings:
    $key_ca74 = { 9d 06 [2] af 24 [2] a9 11 [2] 87 11 [2] b8 0d }

  condition:
    any of them
}