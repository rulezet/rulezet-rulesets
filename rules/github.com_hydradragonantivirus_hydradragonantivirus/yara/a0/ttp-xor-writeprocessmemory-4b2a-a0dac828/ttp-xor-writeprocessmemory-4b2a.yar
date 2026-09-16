rule TTP_XOR_WriteProcessMemory_4b2a {
  strings:
    $key_4b2a = { 1c 58 [2] 2e 7a [2] 28 4f [2] 06 4f [2] 39 53 }

  condition:
    any of them
}