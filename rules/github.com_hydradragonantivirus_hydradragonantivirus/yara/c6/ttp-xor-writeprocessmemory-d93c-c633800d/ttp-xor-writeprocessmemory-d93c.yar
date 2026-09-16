rule TTP_XOR_WriteProcessMemory_d93c {
  strings:
    $key_d93c = { 8e 4e [2] bc 6c [2] ba 59 [2] 94 59 [2] ab 45 }

  condition:
    any of them
}