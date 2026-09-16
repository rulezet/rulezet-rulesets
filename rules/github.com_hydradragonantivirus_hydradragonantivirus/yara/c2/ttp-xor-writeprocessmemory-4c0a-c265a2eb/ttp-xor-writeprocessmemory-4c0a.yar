rule TTP_XOR_WriteProcessMemory_4c0a {
  strings:
    $key_4c0a = { 1b 78 [2] 29 5a [2] 2f 6f [2] 01 6f [2] 3e 73 }

  condition:
    any of them
}