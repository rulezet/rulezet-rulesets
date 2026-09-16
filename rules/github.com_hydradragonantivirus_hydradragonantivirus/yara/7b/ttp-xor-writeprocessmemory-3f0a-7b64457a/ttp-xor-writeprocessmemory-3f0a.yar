rule TTP_XOR_WriteProcessMemory_3f0a {
  strings:
    $key_3f0a = { 68 78 [2] 5a 5a [2] 5c 6f [2] 72 6f [2] 4d 73 }

  condition:
    any of them
}