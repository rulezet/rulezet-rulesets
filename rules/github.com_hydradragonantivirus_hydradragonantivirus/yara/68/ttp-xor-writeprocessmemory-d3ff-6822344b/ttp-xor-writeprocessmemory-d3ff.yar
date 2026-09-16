rule TTP_XOR_WriteProcessMemory_d3ff {
  strings:
    $key_d3ff = { 84 8d [2] b6 af [2] b0 9a [2] 9e 9a [2] a1 86 }

  condition:
    any of them
}