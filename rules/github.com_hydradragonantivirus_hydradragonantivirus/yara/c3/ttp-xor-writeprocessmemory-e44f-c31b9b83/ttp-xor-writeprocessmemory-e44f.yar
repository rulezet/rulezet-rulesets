rule TTP_XOR_WriteProcessMemory_e44f {
  strings:
    $key_e44f = { b3 3d [2] 81 1f [2] 87 2a [2] a9 2a [2] 96 36 }

  condition:
    any of them
}