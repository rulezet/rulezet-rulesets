rule TTP_XOR_WriteProcessMemory_274f {
  strings:
    $key_274f = { 70 3d [2] 42 1f [2] 44 2a [2] 6a 2a [2] 55 36 }

  condition:
    any of them
}