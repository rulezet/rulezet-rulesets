rule TTP_XOR_WriteProcessMemory_cef9 {
  strings:
    $key_cef9 = { 99 8b [2] ab a9 [2] ad 9c [2] 83 9c [2] bc 80 }

  condition:
    any of them
}