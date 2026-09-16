rule TTP_XOR_WriteProcessMemory_f31a {
  strings:
    $key_f31a = { a4 68 [2] 96 4a [2] 90 7f [2] be 7f [2] 81 63 }

  condition:
    any of them
}