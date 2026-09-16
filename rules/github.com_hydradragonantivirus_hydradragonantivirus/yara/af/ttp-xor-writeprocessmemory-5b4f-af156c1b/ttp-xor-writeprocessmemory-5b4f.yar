rule TTP_XOR_WriteProcessMemory_5b4f {
  strings:
    $key_5b4f = { 0c 3d [2] 3e 1f [2] 38 2a [2] 16 2a [2] 29 36 }

  condition:
    any of them
}