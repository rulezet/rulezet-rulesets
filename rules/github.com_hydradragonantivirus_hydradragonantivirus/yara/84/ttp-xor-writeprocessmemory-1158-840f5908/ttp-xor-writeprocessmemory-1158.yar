rule TTP_XOR_WriteProcessMemory_1158 {
  strings:
    $key_1158 = { 46 2a [2] 74 08 [2] 72 3d [2] 5c 3d [2] 63 21 }

  condition:
    any of them
}