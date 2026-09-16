rule TTP_XOR_WriteProcessMemory_cee1 {
  strings:
    $key_cee1 = { 99 93 [2] ab b1 [2] ad 84 [2] 83 84 [2] bc 98 }

  condition:
    any of them
}