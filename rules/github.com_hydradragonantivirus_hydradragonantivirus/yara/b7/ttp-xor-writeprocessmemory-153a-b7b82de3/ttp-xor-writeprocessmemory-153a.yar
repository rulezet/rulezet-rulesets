rule TTP_XOR_WriteProcessMemory_153a {
  strings:
    $key_153a = { 42 48 [2] 70 6a [2] 76 5f [2] 58 5f [2] 67 43 }

  condition:
    any of them
}