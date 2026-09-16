rule TTP_XOR_WriteProcessMemory_764f {
  strings:
    $key_764f = { 21 3d [2] 13 1f [2] 15 2a [2] 3b 2a [2] 04 36 }

  condition:
    any of them
}