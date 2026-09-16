rule TTP_XOR_WriteProcessMemory_643a {
  strings:
    $key_643a = { 33 48 [2] 01 6a [2] 07 5f [2] 29 5f [2] 16 43 }

  condition:
    any of them
}