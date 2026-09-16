rule TTP_XOR_WriteProcessMemory_cef6 {
  strings:
    $key_cef6 = { 99 84 [2] ab a6 [2] ad 93 [2] 83 93 [2] bc 8f }

  condition:
    any of them
}