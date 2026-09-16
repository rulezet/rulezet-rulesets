rule TTP_XOR_WriteProcessMemory_7d0a {
  strings:
    $key_7d0a = { 2a 78 [2] 18 5a [2] 1e 6f [2] 30 6f [2] 0f 73 }

  condition:
    any of them
}