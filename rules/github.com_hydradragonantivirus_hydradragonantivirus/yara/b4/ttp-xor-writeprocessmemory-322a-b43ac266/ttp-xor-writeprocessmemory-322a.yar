rule TTP_XOR_WriteProcessMemory_322a {
  strings:
    $key_322a = { 65 58 [2] 57 7a [2] 51 4f [2] 7f 4f [2] 40 53 }

  condition:
    any of them
}