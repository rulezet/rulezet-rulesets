rule TTP_XOR_WriteProcessMemory_1258 {
  strings:
    $key_1258 = { 45 2a [2] 77 08 [2] 71 3d [2] 5f 3d [2] 60 21 }

  condition:
    any of them
}