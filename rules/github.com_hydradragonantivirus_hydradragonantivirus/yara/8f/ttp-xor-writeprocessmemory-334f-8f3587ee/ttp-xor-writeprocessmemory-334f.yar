rule TTP_XOR_WriteProcessMemory_334f {
  strings:
    $key_334f = { 64 3d [2] 56 1f [2] 50 2a [2] 7e 2a [2] 41 36 }

  condition:
    any of them
}