rule TTP_XOR_WriteProcessMemory_a1ca {
  strings:
    $key_a1ca = { f6 b8 [2] c4 9a [2] c2 af [2] ec af [2] d3 b3 }

  condition:
    any of them
}