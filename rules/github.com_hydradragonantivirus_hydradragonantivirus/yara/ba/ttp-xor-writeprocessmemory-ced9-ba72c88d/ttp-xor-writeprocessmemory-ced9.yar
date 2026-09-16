rule TTP_XOR_WriteProcessMemory_ced9 {
  strings:
    $key_ced9 = { 99 ab [2] ab 89 [2] ad bc [2] 83 bc [2] bc a0 }

  condition:
    any of them
}