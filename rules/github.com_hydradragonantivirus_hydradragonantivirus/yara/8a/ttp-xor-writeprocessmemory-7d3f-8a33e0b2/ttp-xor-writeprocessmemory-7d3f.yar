rule TTP_XOR_WriteProcessMemory_7d3f {
  strings:
    $key_7d3f = { 2a 4d [2] 18 6f [2] 1e 5a [2] 30 5a [2] 0f 46 }

  condition:
    any of them
}