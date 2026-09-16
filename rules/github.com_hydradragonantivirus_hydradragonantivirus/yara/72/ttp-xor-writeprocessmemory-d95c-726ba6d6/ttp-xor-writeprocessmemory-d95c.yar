rule TTP_XOR_WriteProcessMemory_d95c {
  strings:
    $key_d95c = { 8e 2e [2] bc 0c [2] ba 39 [2] 94 39 [2] ab 25 }

  condition:
    any of them
}