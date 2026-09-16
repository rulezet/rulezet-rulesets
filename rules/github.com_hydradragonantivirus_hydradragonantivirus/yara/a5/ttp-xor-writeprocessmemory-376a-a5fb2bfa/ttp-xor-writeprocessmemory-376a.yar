rule TTP_XOR_WriteProcessMemory_376a {
  strings:
    $key_376a = { 60 18 [2] 52 3a [2] 54 0f [2] 7a 0f [2] 45 13 }

  condition:
    any of them
}