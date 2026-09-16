rule TTP_XOR_WriteProcessMemory_115a {
  strings:
    $key_115a = { 46 28 [2] 74 0a [2] 72 3f [2] 5c 3f [2] 63 23 }

  condition:
    any of them
}