rule TTP_XOR_WriteProcessMemory_630a {
  strings:
    $key_630a = { 34 78 [2] 06 5a [2] 00 6f [2] 2e 6f [2] 11 73 }

  condition:
    any of them
}