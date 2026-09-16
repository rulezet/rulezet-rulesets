rule TTP_XOR_WriteProcessMemory_543a {
  strings:
    $key_543a = { 03 48 [2] 31 6a [2] 37 5f [2] 19 5f [2] 26 43 }

  condition:
    any of them
}