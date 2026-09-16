rule TTP_XOR_WriteProcessMemory_7358 {
  strings:
    $key_7358 = { 24 2a [2] 16 08 [2] 10 3d [2] 3e 3d [2] 01 21 }

  condition:
    any of them
}