rule TTP_XOR_WriteProcessMemory_595a {
  strings:
    $key_595a = { 0e 28 [2] 3c 0a [2] 3a 3f [2] 14 3f [2] 2b 23 }

  condition:
    any of them
}