rule TTP_XOR_WriteProcessMemory_7c0a {
  strings:
    $key_7c0a = { 2b 78 [2] 19 5a [2] 1f 6f [2] 31 6f [2] 0e 73 }

  condition:
    any of them
}