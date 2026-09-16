rule TTP_XOR_WriteProcessMemory_7e2a {
  strings:
    $key_7e2a = { 29 58 [2] 1b 7a [2] 1d 4f [2] 33 4f [2] 0c 53 }

  condition:
    any of them
}