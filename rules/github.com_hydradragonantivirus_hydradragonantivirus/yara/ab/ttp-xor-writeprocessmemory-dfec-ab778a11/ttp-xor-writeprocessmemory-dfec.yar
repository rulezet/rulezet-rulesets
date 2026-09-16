rule TTP_XOR_WriteProcessMemory_dfec {
  strings:
    $key_dfec = { 88 9e [2] ba bc [2] bc 89 [2] 92 89 [2] ad 95 }

  condition:
    any of them
}