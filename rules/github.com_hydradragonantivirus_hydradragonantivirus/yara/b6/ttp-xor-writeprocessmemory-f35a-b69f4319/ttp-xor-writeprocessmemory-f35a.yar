rule TTP_XOR_WriteProcessMemory_f35a {
  strings:
    $key_f35a = { a4 28 [2] 96 0a [2] 90 3f [2] be 3f [2] 81 23 }

  condition:
    any of them
}