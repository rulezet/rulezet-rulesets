rule TTP_XOR_WriteProcessMemory_d99a {
  strings:
    $key_d99a = { 8e e8 [2] bc ca [2] ba ff [2] 94 ff [2] ab e3 }

  condition:
    any of them
}