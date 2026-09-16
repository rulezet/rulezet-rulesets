rule TTP_XOR_WriteProcessMemory_b04a {
  strings:
    $key_b04a = { e7 38 [2] d5 1a [2] d3 2f [2] fd 2f [2] c2 33 }

  condition:
    any of them
}