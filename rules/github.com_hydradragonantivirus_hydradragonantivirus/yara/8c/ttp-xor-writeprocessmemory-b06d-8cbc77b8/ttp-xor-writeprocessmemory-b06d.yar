rule TTP_XOR_WriteProcessMemory_b06d {
  strings:
    $key_b06d = { e7 1f [2] d5 3d [2] d3 08 [2] fd 08 [2] c2 14 }

  condition:
    any of them
}