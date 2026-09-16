rule TTP_XOR_WriteProcessMemory_cef8 {
  strings:
    $key_cef8 = { 99 8a [2] ab a8 [2] ad 9d [2] 83 9d [2] bc 81 }

  condition:
    any of them
}