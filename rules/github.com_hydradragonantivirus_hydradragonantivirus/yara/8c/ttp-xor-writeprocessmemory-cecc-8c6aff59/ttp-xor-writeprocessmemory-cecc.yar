rule TTP_XOR_WriteProcessMemory_cecc {
  strings:
    $key_cecc = { 99 be [2] ab 9c [2] ad a9 [2] 83 a9 [2] bc b5 }

  condition:
    any of them
}