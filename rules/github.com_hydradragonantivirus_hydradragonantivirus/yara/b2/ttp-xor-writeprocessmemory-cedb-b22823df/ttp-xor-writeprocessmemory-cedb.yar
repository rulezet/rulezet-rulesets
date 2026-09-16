rule TTP_XOR_WriteProcessMemory_cedb {
  strings:
    $key_cedb = { 99 a9 [2] ab 8b [2] ad be [2] 83 be [2] bc a2 }

  condition:
    any of them
}