rule TTP_XOR_WriteProcessMemory_d9fd {
  strings:
    $key_d9fd = { 8e 8f [2] bc ad [2] ba 98 [2] 94 98 [2] ab 84 }

  condition:
    any of them
}