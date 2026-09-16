rule TTP_XOR_WriteProcessMemory_7d2a {
  strings:
    $key_7d2a = { 2a 58 [2] 18 7a [2] 1e 4f [2] 30 4f [2] 0f 53 }

  condition:
    any of them
}