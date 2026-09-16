rule TTP_XOR_WriteProcessMemory_d9ee {
  strings:
    $key_d9ee = { 8e 9c [2] bc be [2] ba 8b [2] 94 8b [2] ab 97 }

  condition:
    any of them
}