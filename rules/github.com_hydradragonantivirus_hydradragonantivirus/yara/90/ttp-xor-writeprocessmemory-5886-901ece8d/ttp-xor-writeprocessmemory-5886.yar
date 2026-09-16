rule TTP_XOR_WriteProcessMemory_5886 {
  strings:
    $key_5886 = { 0f f4 [2] 3d d6 [2] 3b e3 [2] 15 e3 [2] 2a ff }

  condition:
    any of them
}