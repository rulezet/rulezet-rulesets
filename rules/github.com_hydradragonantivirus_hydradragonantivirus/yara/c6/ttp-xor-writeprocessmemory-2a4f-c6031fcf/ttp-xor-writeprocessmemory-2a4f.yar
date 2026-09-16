rule TTP_XOR_WriteProcessMemory_2a4f {
  strings:
    $key_2a4f = { 7d 3d [2] 4f 1f [2] 49 2a [2] 67 2a [2] 58 36 }

  condition:
    any of them
}