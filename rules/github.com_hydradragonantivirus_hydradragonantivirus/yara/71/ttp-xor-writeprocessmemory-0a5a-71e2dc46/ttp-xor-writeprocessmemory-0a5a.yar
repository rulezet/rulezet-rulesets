rule TTP_XOR_WriteProcessMemory_0a5a {
  strings:
    $key_0a5a = { 5d 28 [2] 6f 0a [2] 69 3f [2] 47 3f [2] 78 23 }

  condition:
    any of them
}