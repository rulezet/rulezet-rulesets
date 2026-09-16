rule TTP_XOR_WriteProcessMemory_397a {
  strings:
    $key_397a = { 6e 08 [2] 5c 2a [2] 5a 1f [2] 74 1f [2] 4b 03 }

  condition:
    any of them
}