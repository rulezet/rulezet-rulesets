rule TTP_XOR_WriteProcessMemory_a11f {
  strings:
    $key_a11f = { f6 6d [2] c4 4f [2] c2 7a [2] ec 7a [2] d3 66 }

  condition:
    any of them
}