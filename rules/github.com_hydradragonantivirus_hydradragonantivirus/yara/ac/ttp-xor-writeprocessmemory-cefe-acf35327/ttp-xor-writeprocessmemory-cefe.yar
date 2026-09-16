rule TTP_XOR_WriteProcessMemory_cefe {
  strings:
    $key_cefe = { 99 8c [2] ab ae [2] ad 9b [2] 83 9b [2] bc 87 }

  condition:
    any of them
}