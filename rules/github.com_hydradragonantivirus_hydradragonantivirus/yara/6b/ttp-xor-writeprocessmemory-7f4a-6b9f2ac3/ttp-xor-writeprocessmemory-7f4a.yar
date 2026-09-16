rule TTP_XOR_WriteProcessMemory_7f4a {
  strings:
    $key_7f4a = { 28 38 [2] 1a 1a [2] 1c 2f [2] 32 2f [2] 0d 33 }

  condition:
    any of them
}