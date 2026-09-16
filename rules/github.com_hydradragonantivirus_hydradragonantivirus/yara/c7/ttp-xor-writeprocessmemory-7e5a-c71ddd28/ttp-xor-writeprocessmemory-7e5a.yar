rule TTP_XOR_WriteProcessMemory_7e5a {
  strings:
    $key_7e5a = { 29 28 [2] 1b 0a [2] 1d 3f [2] 33 3f [2] 0c 23 }

  condition:
    any of them
}