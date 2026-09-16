rule TTP_XOR_WriteProcessMemory_c82f {
  strings:
    $key_c82f = { 9f 5d [2] ad 7f [2] ab 4a [2] 85 4a [2] ba 56 }

  condition:
    any of them
}