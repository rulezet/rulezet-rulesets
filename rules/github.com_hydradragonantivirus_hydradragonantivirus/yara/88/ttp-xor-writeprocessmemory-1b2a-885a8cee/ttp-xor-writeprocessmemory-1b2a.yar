rule TTP_XOR_WriteProcessMemory_1b2a {
  strings:
    $key_1b2a = { 4c 58 [2] 7e 7a [2] 78 4f [2] 56 4f [2] 69 53 }

  condition:
    any of them
}