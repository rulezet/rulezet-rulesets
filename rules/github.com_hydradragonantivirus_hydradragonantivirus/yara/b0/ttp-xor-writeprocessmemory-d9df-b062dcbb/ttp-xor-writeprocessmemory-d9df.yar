rule TTP_XOR_WriteProcessMemory_d9df {
  strings:
    $key_d9df = { 8e ad [2] bc 8f [2] ba ba [2] 94 ba [2] ab a6 }

  condition:
    any of them
}