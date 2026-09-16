rule TTP_XOR_WriteProcessMemory_cefb {
  strings:
    $key_cefb = { 99 89 [2] ab ab [2] ad 9e [2] 83 9e [2] bc 82 }

  condition:
    any of them
}