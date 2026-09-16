rule TTP_XOR_WriteProcessMemory_cecd {
  strings:
    $key_cecd = { 99 bf [2] ab 9d [2] ad a8 [2] 83 a8 [2] bc b4 }

  condition:
    any of them
}