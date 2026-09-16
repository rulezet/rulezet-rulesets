rule TTP_XOR_WriteProcessMemory_f30a {
  strings:
    $key_f30a = { a4 78 [2] 96 5a [2] 90 6f [2] be 6f [2] 81 73 }

  condition:
    any of them
}