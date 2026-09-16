rule TTP_XOR_WriteProcessMemory_3b4a {
  strings:
    $key_3b4a = { 6c 38 [2] 5e 1a [2] 58 2f [2] 76 2f [2] 49 33 }

  condition:
    any of them
}