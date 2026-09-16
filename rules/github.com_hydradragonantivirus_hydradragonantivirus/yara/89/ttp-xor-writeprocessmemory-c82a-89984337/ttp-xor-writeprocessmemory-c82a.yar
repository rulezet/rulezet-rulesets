rule TTP_XOR_WriteProcessMemory_c82a {
  strings:
    $key_c82a = { 9f 58 [2] ad 7a [2] ab 4f [2] 85 4f [2] ba 53 }

  condition:
    any of them
}