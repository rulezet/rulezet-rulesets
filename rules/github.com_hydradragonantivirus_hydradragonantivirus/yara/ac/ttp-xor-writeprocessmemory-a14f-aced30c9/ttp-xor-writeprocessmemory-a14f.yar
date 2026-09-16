rule TTP_XOR_WriteProcessMemory_a14f {
  strings:
    $key_a14f = { f6 3d [2] c4 1f [2] c2 2a [2] ec 2a [2] d3 36 }

  condition:
    any of them
}