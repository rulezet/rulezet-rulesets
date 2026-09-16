rule TTP_XOR_WriteProcessMemory_2d6a {
  strings:
    $key_2d6a = { 7a 18 [2] 48 3a [2] 4e 0f [2] 60 0f [2] 5f 13 }

  condition:
    any of them
}