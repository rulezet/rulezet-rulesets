rule TTP_XOR_WriteProcessMemory_3158 {
  strings:
    $key_3158 = { 66 2a [2] 54 08 [2] 52 3d [2] 7c 3d [2] 43 21 }

  condition:
    any of them
}