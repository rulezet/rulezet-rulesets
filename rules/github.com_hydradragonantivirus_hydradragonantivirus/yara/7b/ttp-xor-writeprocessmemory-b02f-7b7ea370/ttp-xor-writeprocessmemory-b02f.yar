rule TTP_XOR_WriteProcessMemory_b02f {
  strings:
    $key_b02f = { e7 5d [2] d5 7f [2] d3 4a [2] fd 4a [2] c2 56 }

  condition:
    any of them
}