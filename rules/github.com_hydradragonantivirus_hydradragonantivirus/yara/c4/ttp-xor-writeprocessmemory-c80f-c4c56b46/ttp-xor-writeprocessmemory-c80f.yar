rule TTP_XOR_WriteProcessMemory_c80f {
  strings:
    $key_c80f = { 9f 7d [2] ad 5f [2] ab 6a [2] 85 6a [2] ba 76 }

  condition:
    any of them
}