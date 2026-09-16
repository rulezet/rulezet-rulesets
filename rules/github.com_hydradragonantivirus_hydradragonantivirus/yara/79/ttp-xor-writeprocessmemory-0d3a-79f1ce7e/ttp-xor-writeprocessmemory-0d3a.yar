rule TTP_XOR_WriteProcessMemory_0d3a {
  strings:
    $key_0d3a = { 5a 48 [2] 68 6a [2] 6e 5f [2] 40 5f [2] 7f 43 }

  condition:
    any of them
}