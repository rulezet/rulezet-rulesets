rule TTP_XOR_WriteProcessMemory_562a {
  strings:
    $key_562a = { 01 58 [2] 33 7a [2] 35 4f [2] 1b 4f [2] 24 53 }

  condition:
    any of them
}