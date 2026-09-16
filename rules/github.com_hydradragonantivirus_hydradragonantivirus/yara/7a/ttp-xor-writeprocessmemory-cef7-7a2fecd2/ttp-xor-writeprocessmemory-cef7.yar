rule TTP_XOR_WriteProcessMemory_cef7 {
  strings:
    $key_cef7 = { 99 85 [2] ab a7 [2] ad 92 [2] 83 92 [2] bc 8e }

  condition:
    any of them
}