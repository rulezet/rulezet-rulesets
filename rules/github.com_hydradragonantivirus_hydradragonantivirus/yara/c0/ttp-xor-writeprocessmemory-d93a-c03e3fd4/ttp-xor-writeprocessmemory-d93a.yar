rule TTP_XOR_WriteProcessMemory_d93a {
  strings:
    $key_d93a = { 8e 48 [2] bc 6a [2] ba 5f [2] 94 5f [2] ab 43 }

  condition:
    any of them
}