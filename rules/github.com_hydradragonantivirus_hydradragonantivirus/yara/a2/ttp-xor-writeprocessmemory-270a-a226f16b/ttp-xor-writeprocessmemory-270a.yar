rule TTP_XOR_WriteProcessMemory_270a {
  strings:
    $key_270a = { 70 78 [2] 42 5a [2] 44 6f [2] 6a 6f [2] 55 73 }

  condition:
    any of them
}