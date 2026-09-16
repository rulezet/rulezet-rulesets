rule TTP_XOR_WriteProcessMemory_4e0a {
  strings:
    $key_4e0a = { 19 78 [2] 2b 5a [2] 2d 6f [2] 03 6f [2] 3c 73 }

  condition:
    any of them
}