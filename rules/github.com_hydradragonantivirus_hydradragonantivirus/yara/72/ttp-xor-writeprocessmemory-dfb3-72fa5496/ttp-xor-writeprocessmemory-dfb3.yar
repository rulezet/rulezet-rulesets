rule TTP_XOR_WriteProcessMemory_dfb3 {
  strings:
    $key_dfb3 = { 88 c1 [2] ba e3 [2] bc d6 [2] 92 d6 [2] ad ca }

  condition:
    any of them
}