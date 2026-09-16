rule TTP_XOR_WriteProcessMemory_3b4f {
  strings:
    $key_3b4f = { 6c 3d [2] 5e 1f [2] 58 2a [2] 76 2a [2] 49 36 }

  condition:
    any of them
}