rule TTP_XOR_WriteProcessMemory_f36a {
  strings:
    $key_f36a = { a4 18 [2] 96 3a [2] 90 0f [2] be 0f [2] 81 13 }

  condition:
    any of them
}