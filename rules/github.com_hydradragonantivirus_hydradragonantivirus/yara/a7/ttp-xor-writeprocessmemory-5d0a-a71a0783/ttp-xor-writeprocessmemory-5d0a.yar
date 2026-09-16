rule TTP_XOR_WriteProcessMemory_5d0a {
  strings:
    $key_5d0a = { 0a 78 [2] 38 5a [2] 3e 6f [2] 10 6f [2] 2f 73 }

  condition:
    any of them
}