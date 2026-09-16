rule TTP_XOR_WriteProcessMemory_024f {
  strings:
    $key_024f = { 55 3d [2] 67 1f [2] 61 2a [2] 4f 2a [2] 70 36 }

  condition:
    any of them
}