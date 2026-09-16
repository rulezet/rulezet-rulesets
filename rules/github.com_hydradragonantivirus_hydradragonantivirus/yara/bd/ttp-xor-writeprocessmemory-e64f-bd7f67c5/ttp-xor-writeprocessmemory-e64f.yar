rule TTP_XOR_WriteProcessMemory_e64f {
  strings:
    $key_e64f = { b1 3d [2] 83 1f [2] 85 2a [2] ab 2a [2] 94 36 }

  condition:
    any of them
}