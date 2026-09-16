rule TTP_XOR_WriteProcessMemory_0058 {
  strings:
    $key_0058 = { 57 2a [2] 65 08 [2] 63 3d [2] 4d 3d [2] 72 21 }

  condition:
    any of them
}