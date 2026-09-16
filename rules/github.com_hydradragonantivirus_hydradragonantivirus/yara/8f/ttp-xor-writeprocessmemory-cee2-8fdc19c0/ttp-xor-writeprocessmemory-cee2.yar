rule TTP_XOR_WriteProcessMemory_cee2 {
  strings:
    $key_cee2 = { 99 90 [2] ab b2 [2] ad 87 [2] 83 87 [2] bc 9b }

  condition:
    any of them
}