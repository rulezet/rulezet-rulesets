rule TTP_XOR_WriteProcessMemory_fefa {
  strings:
    $key_fefa = { a9 88 [2] 9b aa [2] 9d 9f [2] b3 9f [2] 8c 83 }

  condition:
    any of them
}