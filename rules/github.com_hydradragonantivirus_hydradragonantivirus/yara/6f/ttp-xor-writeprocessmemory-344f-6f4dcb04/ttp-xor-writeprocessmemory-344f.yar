rule TTP_XOR_WriteProcessMemory_344f {
  strings:
    $key_344f = { 63 3d [2] 51 1f [2] 57 2a [2] 79 2a [2] 46 36 }

  condition:
    any of them
}