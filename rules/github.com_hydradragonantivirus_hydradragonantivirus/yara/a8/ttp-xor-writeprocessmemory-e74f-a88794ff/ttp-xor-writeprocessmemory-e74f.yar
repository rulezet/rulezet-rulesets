rule TTP_XOR_WriteProcessMemory_e74f {
  strings:
    $key_e74f = { b0 3d [2] 82 1f [2] 84 2a [2] aa 2a [2] 95 36 }

  condition:
    any of them
}