rule TTP_XOR_WriteProcessMemory_c85d {
  strings:
    $key_c85d = { 9f 2f [2] ad 0d [2] ab 38 [2] 85 38 [2] ba 24 }

  condition:
    any of them
}