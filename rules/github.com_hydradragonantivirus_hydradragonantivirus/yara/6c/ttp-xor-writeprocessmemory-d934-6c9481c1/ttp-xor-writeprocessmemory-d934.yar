rule TTP_XOR_WriteProcessMemory_d934 {
  strings:
    $key_d934 = { 8e 46 [2] bc 64 [2] ba 51 [2] 94 51 [2] ab 4d }

  condition:
    any of them
}