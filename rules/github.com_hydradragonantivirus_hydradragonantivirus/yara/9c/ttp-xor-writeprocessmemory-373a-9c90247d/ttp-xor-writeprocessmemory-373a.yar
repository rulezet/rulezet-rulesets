rule TTP_XOR_WriteProcessMemory_373a {
  strings:
    $key_373a = { 60 48 [2] 52 6a [2] 54 5f [2] 7a 5f [2] 45 43 }

  condition:
    any of them
}