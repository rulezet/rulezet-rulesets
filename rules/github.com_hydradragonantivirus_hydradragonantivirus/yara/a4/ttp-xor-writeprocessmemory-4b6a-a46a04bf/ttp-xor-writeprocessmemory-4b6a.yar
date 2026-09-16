rule TTP_XOR_WriteProcessMemory_4b6a {
  strings:
    $key_4b6a = { 1c 18 [2] 2e 3a [2] 28 0f [2] 06 0f [2] 39 13 }

  condition:
    any of them
}