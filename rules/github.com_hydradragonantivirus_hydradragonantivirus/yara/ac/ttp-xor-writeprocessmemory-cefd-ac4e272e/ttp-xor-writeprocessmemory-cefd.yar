rule TTP_XOR_WriteProcessMemory_cefd {
  strings:
    $key_cefd = { 99 8f [2] ab ad [2] ad 98 [2] 83 98 [2] bc 84 }

  condition:
    any of them
}