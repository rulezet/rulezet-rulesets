rule TTP_XOR_WriteProcessMemory_774f {
  strings:
    $key_774f = { 20 3d [2] 12 1f [2] 14 2a [2] 3a 2a [2] 05 36 }

  condition:
    any of them
}