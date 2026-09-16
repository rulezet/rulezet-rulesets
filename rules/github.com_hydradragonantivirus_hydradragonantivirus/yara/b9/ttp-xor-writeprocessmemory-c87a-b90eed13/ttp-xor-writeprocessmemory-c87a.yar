rule TTP_XOR_WriteProcessMemory_c87a {
  strings:
    $key_c87a = { 9f 08 [2] ad 2a [2] ab 1f [2] 85 1f [2] ba 03 }

  condition:
    any of them
}