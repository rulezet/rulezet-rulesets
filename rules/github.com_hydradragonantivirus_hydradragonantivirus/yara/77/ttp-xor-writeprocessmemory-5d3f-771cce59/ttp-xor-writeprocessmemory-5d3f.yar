rule TTP_XOR_WriteProcessMemory_5d3f {
  strings:
    $key_5d3f = { 0a 4d [2] 38 6f [2] 3e 5a [2] 10 5a [2] 2f 46 }

  condition:
    any of them
}