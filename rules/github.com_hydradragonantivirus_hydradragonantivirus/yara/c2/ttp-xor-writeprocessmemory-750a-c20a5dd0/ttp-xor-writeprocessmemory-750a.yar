rule TTP_XOR_WriteProcessMemory_750a {
  strings:
    $key_750a = { 22 78 [2] 10 5a [2] 16 6f [2] 38 6f [2] 07 73 }

  condition:
    any of them
}