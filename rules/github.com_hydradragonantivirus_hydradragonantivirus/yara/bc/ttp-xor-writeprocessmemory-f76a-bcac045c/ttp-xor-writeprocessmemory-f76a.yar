rule TTP_XOR_WriteProcessMemory_f76a {
  strings:
    $key_f76a = { a0 18 [2] 92 3a [2] 94 0f [2] ba 0f [2] 85 13 }

  condition:
    any of them
}