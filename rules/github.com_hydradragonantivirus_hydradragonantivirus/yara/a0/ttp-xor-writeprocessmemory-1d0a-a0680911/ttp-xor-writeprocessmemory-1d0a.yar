rule TTP_XOR_WriteProcessMemory_1d0a {
  strings:
    $key_1d0a = { 4a 78 [2] 78 5a [2] 7e 6f [2] 50 6f [2] 6f 73 }

  condition:
    any of them
}