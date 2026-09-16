rule TTP_XOR_WriteProcessMemory_dfdc {
  strings:
    $key_dfdc = { 88 ae [2] ba 8c [2] bc b9 [2] 92 b9 [2] ad a5 }

  condition:
    any of them
}