rule TTP_XOR_WriteProcessMemory_697a {
  strings:
    $key_697a = { 3e 08 [2] 0c 2a [2] 0a 1f [2] 24 1f [2] 1b 03 }

  condition:
    any of them
}