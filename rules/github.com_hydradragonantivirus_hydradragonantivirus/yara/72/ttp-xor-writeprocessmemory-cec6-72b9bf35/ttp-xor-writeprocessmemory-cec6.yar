rule TTP_XOR_WriteProcessMemory_cec6 {
  strings:
    $key_cec6 = { 99 b4 [2] ab 96 [2] ad a3 [2] 83 a3 [2] bc bf }

  condition:
    any of them
}