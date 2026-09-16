rule TTP_XOR_WriteProcessMemory_f3fa {
  strings:
    $key_f3fa = { a4 88 [2] 96 aa [2] 90 9f [2] be 9f [2] 81 83 }

  condition:
    any of them
}