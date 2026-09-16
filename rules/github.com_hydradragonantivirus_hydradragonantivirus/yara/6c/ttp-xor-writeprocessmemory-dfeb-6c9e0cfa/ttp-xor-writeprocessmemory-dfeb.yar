rule TTP_XOR_WriteProcessMemory_dfeb {
  strings:
    $key_dfeb = { 88 99 [2] ba bb [2] bc 8e [2] 92 8e [2] ad 92 }

  condition:
    any of them
}