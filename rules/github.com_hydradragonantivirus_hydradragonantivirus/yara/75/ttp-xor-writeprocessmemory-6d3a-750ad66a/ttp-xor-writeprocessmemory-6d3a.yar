rule TTP_XOR_WriteProcessMemory_6d3a {
  strings:
    $key_6d3a = { 3a 48 [2] 08 6a [2] 0e 5f [2] 20 5f [2] 1f 43 }

  condition:
    any of them
}