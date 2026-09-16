rule TTP_XOR_WriteProcessMemory_6d3f {
  strings:
    $key_6d3f = { 3a 4d [2] 08 6f [2] 0e 5a [2] 20 5a [2] 1f 46 }

  condition:
    any of them
}