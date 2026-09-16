rule TTP_XOR_WriteProcessMemory_d9ca {
  strings:
    $key_d9ca = { 8e b8 [2] bc 9a [2] ba af [2] 94 af [2] ab b3 }

  condition:
    any of them
}