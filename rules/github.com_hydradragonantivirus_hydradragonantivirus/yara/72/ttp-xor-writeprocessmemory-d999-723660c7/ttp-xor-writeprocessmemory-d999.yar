rule TTP_XOR_WriteProcessMemory_d999 {
  strings:
    $key_d999 = { 8e eb [2] bc c9 [2] ba fc [2] 94 fc [2] ab e0 }

  condition:
    any of them
}