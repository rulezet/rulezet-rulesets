rule TTP_XOR_WriteProcessMemory_7561 {
  strings:
    $key_7561 = { 22 13 [2] 10 31 [2] 16 04 [2] 38 04 [2] 07 18 }

  condition:
    any of them
}