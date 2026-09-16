rule TTP_XOR_WriteProcessMemory_204f {
  strings:
    $key_204f = { 77 3d [2] 45 1f [2] 43 2a [2] 6d 2a [2] 52 36 }

  condition:
    any of them
}