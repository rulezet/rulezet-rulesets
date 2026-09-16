rule TTP_XOR_WriteProcessMemory_2648 {
  strings:
    $key_2648 = { 71 3a [2] 43 18 [2] 45 2d [2] 6b 2d [2] 54 31 }

  condition:
    any of them
}