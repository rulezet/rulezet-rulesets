rule TTP_XOR_WriteProcessMemory_c87f {
  strings:
    $key_c87f = { 9f 0d [2] ad 2f [2] ab 1a [2] 85 1a [2] ba 06 }

  condition:
    any of them
}