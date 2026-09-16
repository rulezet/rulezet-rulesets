rule TTP_XOR_WriteProcessMemory_4b3a {
  strings:
    $key_4b3a = { 1c 48 [2] 2e 6a [2] 28 5f [2] 06 5f [2] 39 43 }

  condition:
    any of them
}