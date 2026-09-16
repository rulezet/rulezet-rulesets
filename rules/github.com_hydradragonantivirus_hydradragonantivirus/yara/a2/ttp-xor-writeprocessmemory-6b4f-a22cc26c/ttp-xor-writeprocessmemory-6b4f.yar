rule TTP_XOR_WriteProcessMemory_6b4f {
  strings:
    $key_6b4f = { 3c 3d [2] 0e 1f [2] 08 2a [2] 26 2a [2] 19 36 }

  condition:
    any of them
}