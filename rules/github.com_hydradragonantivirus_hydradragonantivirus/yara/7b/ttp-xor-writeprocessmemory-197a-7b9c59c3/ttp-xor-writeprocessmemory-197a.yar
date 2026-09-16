rule TTP_XOR_WriteProcessMemory_197a {
  strings:
    $key_197a = { 4e 08 [2] 7c 2a [2] 7a 1f [2] 54 1f [2] 6b 03 }

  condition:
    any of them
}