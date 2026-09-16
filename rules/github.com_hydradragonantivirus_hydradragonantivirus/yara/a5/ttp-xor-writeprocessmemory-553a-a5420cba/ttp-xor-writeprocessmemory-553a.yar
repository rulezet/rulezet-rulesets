rule TTP_XOR_WriteProcessMemory_553a {
  strings:
    $key_553a = { 02 48 [2] 30 6a [2] 36 5f [2] 18 5f [2] 27 43 }

  condition:
    any of them
}