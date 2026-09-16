rule TTP_XOR_WriteProcessMemory_266a {
  strings:
    $key_266a = { 71 18 [2] 43 3a [2] 45 0f [2] 6b 0f [2] 54 13 }

  condition:
    any of them
}