rule TTP_XOR_WriteProcessMemory_3b5a {
  strings:
    $key_3b5a = { 6c 28 [2] 5e 0a [2] 58 3f [2] 76 3f [2] 49 23 }

  condition:
    any of them
}