rule TTP_XOR_WriteProcessMemory_4d4f {
  strings:
    $key_4d4f = { 1a 3d [2] 28 1f [2] 2e 2a [2] 00 2a [2] 3f 36 }

  condition:
    any of them
}