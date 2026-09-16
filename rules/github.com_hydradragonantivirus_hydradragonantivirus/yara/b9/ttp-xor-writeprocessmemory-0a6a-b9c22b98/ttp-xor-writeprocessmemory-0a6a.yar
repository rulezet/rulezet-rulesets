rule TTP_XOR_WriteProcessMemory_0a6a {
  strings:
    $key_0a6a = { 5d 18 [2] 6f 3a [2] 69 0f [2] 47 0f [2] 78 13 }

  condition:
    any of them
}