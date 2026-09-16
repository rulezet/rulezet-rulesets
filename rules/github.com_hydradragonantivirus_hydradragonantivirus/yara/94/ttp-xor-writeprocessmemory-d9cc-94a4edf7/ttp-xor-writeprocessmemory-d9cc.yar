rule TTP_XOR_WriteProcessMemory_d9cc {
  strings:
    $key_d9cc = { 8e be [2] bc 9c [2] ba a9 [2] 94 a9 [2] ab b5 }

  condition:
    any of them
}