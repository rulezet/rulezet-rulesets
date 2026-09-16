rule TTP_XOR_WriteProcessMemory_0a3a {
  strings:
    $key_0a3a = { 5d 48 [2] 6f 6a [2] 69 5f [2] 47 5f [2] 78 43 }

  condition:
    any of them
}