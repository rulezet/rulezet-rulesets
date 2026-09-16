rule TTP_XOR_WriteProcessMemory_644f {
  strings:
    $key_644f = { 33 3d [2] 01 1f [2] 07 2a [2] 29 2a [2] 16 36 }

  condition:
    any of them
}