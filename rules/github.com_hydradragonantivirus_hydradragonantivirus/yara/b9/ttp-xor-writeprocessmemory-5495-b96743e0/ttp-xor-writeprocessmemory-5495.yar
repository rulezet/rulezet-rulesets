rule TTP_XOR_WriteProcessMemory_5495 {
  strings:
    $key_5495 = { 03 e7 [2] 31 c5 [2] 37 f0 [2] 19 f0 [2] 26 ec }

  condition:
    any of them
}