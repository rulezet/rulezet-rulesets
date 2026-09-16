rule TTP_XOR_WriteProcessMemory_253a {
  strings:
    $key_253a = { 72 48 [2] 40 6a [2] 46 5f [2] 68 5f [2] 57 43 }

  condition:
    any of them
}