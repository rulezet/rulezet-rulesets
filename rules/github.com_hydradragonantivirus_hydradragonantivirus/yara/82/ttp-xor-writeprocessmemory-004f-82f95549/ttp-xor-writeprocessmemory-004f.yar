rule TTP_XOR_WriteProcessMemory_004f {
  strings:
    $key_004f = { 57 3d [2] 65 1f [2] 63 2a [2] 4d 2a [2] 72 36 }

  condition:
    any of them
}