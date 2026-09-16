rule TTP_XOR_WriteProcessMemory_550a {
  strings:
    $key_550a = { 02 78 [2] 30 5a [2] 36 6f [2] 18 6f [2] 27 73 }

  condition:
    any of them
}