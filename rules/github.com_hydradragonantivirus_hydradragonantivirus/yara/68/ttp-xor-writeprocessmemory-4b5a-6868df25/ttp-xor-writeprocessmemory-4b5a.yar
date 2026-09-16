rule TTP_XOR_WriteProcessMemory_4b5a {
  strings:
    $key_4b5a = { 1c 28 [2] 2e 0a [2] 28 3f [2] 06 3f [2] 39 23 }

  condition:
    any of them
}