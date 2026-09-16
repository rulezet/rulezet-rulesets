rule TTP_XOR_WriteProcessMemory_4d3f {
  strings:
    $key_4d3f = { 1a 4d [2] 28 6f [2] 2e 5a [2] 00 5a [2] 3f 46 }

  condition:
    any of them
}