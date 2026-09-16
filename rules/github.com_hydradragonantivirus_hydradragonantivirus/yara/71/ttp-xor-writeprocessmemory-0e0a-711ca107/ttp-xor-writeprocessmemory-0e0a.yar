rule TTP_XOR_WriteProcessMemory_0e0a {
  strings:
    $key_0e0a = { 59 78 [2] 6b 5a [2] 6d 6f [2] 43 6f [2] 7c 73 }

  condition:
    any of them
}