rule TTP_XOR_WriteProcessMemory_442a {
  strings:
    $key_442a = { 13 58 [2] 21 7a [2] 27 4f [2] 09 4f [2] 36 53 }

  condition:
    any of them
}