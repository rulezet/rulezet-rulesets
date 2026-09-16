rule TTP_XOR_WriteProcessMemory_226a {
  strings:
    $key_226a = { 75 18 [2] 47 3a [2] 41 0f [2] 6f 0f [2] 50 13 }

  condition:
    any of them
}