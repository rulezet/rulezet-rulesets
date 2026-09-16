rule TTP_XOR_WriteProcessMemory_3f4f {
  strings:
    $key_3f4f = { 68 3d [2] 5a 1f [2] 5c 2a [2] 72 2a [2] 4d 36 }

  condition:
    any of them
}