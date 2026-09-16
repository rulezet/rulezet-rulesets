rule TTP_XOR_WriteProcessMemory_0458 {
  strings:
    $key_0458 = { 53 2a [2] 61 08 [2] 67 3d [2] 49 3d [2] 76 21 }

  condition:
    any of them
}