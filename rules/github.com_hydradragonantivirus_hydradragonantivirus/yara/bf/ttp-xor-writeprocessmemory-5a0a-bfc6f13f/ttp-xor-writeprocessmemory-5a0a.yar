rule TTP_XOR_WriteProcessMemory_5a0a {
  strings:
    $key_5a0a = { 0d 78 [2] 3f 5a [2] 39 6f [2] 17 6f [2] 28 73 }

  condition:
    any of them
}