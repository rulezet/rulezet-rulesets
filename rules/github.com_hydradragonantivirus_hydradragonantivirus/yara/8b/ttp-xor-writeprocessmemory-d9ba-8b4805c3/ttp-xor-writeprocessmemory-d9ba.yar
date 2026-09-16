rule TTP_XOR_WriteProcessMemory_d9ba {
  strings:
    $key_d9ba = { 8e c8 [2] bc ea [2] ba df [2] 94 df [2] ab c3 }

  condition:
    any of them
}