rule TTP_XOR_WriteProcessMemory_0258 {
  strings:
    $key_0258 = { 55 2a [2] 67 08 [2] 61 3d [2] 4f 3d [2] 70 21 }

  condition:
    any of them
}