rule TTP_XOR_WriteProcessMemory_4a0a {
  strings:
    $key_4a0a = { 1d 78 [2] 2f 5a [2] 29 6f [2] 07 6f [2] 38 73 }

  condition:
    any of them
}