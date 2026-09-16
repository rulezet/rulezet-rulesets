rule TTP_XOR_WriteProcessMemory_b01f {
  strings:
    $key_b01f = { e7 6d [2] d5 4f [2] d3 7a [2] fd 7a [2] c2 66 }

  condition:
    any of them
}