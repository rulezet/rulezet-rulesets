rule TTP_XOR_WriteProcessMemory_ed4f {
  strings:
    $key_ed4f = { ba 3d [2] 88 1f [2] 8e 2a [2] a0 2a [2] 9f 36 }

  condition:
    any of them
}