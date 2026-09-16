rule TTP_XOR_WriteProcessMemory_234a {
  strings:
    $key_234a = { 74 38 [2] 46 1a [2] 40 2f [2] 6e 2f [2] 51 33 }

  condition:
    any of them
}