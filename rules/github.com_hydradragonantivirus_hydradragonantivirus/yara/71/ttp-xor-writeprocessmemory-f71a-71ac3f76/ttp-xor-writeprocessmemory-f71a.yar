rule TTP_XOR_WriteProcessMemory_f71a {
  strings:
    $key_f71a = { a0 68 [2] 92 4a [2] 94 7f [2] ba 7f [2] 85 63 }

  condition:
    any of them
}