rule TTP_XOR_WriteProcessMemory_f35d {
  strings:
    $key_f35d = { a4 2f [2] 96 0d [2] 90 38 [2] be 38 [2] 81 24 }

  condition:
    any of them
}