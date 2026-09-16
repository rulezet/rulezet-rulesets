rule TTP_XOR_WriteProcessMemory_f34a {
  strings:
    $key_f34a = { a4 38 [2] 96 1a [2] 90 2f [2] be 2f [2] 81 33 }

  condition:
    any of them
}