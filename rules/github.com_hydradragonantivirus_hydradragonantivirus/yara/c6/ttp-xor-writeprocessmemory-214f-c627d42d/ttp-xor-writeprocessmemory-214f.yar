rule TTP_XOR_WriteProcessMemory_214f {
  strings:
    $key_214f = { 76 3d [2] 44 1f [2] 42 2a [2] 6c 2a [2] 53 36 }

  condition:
    any of them
}