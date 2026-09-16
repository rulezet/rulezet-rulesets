rule TTP_XOR_WriteProcessMemory_cee3 {
  strings:
    $key_cee3 = { 99 91 [2] ab b3 [2] ad 86 [2] 83 86 [2] bc 9a }

  condition:
    any of them
}