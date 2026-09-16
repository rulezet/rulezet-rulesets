rule TTP_XOR_WriteProcessMemory_7d4f {
  strings:
    $key_7d4f = { 2a 3d [2] 18 1f [2] 1e 2a [2] 30 2a [2] 0f 36 }

  condition:
    any of them
}