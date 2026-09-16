rule TTP_XOR_WriteProcessMemory_c83f {
  strings:
    $key_c83f = { 9f 4d [2] ad 6f [2] ab 5a [2] 85 5a [2] ba 46 }

  condition:
    any of them
}