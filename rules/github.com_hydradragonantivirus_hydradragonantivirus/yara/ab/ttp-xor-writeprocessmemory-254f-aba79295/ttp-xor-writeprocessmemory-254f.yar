rule TTP_XOR_WriteProcessMemory_254f {
  strings:
    $key_254f = { 72 3d [2] 40 1f [2] 46 2a [2] 68 2a [2] 57 36 }

  condition:
    any of them
}