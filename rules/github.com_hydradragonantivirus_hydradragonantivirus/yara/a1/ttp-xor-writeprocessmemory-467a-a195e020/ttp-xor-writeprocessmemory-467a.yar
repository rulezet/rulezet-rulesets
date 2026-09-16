rule TTP_XOR_WriteProcessMemory_467a {
  strings:
    $key_467a = { 11 08 [2] 23 2a [2] 25 1f [2] 0b 1f [2] 34 03 }

  condition:
    any of them
}