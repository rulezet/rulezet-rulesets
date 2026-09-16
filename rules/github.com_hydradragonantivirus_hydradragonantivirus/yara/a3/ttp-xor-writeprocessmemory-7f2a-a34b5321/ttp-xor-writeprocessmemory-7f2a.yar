rule TTP_XOR_WriteProcessMemory_7f2a {
  strings:
    $key_7f2a = { 28 58 [2] 1a 7a [2] 1c 4f [2] 32 4f [2] 0d 53 }

  condition:
    any of them
}