rule TTP_XOR_WriteProcessMemory_776a {
  strings:
    $key_776a = { 20 18 [2] 12 3a [2] 14 0f [2] 3a 0f [2] 05 13 }

  condition:
    any of them
}