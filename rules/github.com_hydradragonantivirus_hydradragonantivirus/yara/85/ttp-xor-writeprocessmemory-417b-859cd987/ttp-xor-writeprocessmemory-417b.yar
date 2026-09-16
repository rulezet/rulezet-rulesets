rule TTP_XOR_WriteProcessMemory_417b {
  strings:
    $key_417b = { 16 09 [2] 24 2b [2] 22 1e [2] 0c 1e [2] 33 02 }

  condition:
    any of them
}