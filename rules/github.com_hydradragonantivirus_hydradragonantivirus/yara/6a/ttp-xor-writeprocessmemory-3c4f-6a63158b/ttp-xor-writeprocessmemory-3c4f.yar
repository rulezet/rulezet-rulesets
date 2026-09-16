rule TTP_XOR_WriteProcessMemory_3c4f {
  strings:
    $key_3c4f = { 6b 3d [2] 59 1f [2] 5f 2a [2] 71 2a [2] 4e 36 }

  condition:
    any of them
}