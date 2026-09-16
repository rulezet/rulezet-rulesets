rule TTP_XOR_WriteProcessMemory_622a {
  strings:
    $key_622a = { 35 58 [2] 07 7a [2] 01 4f [2] 2f 4f [2] 10 53 }

  condition:
    any of them
}