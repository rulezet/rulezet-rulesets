rule TTP_XOR_WriteProcessMemory_eb4f {
  strings:
    $key_eb4f = { bc 3d [2] 8e 1f [2] 88 2a [2] a6 2a [2] 99 36 }

  condition:
    any of them
}