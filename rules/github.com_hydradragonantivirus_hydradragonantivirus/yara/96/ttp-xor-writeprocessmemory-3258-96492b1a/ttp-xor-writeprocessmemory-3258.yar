rule TTP_XOR_WriteProcessMemory_3258 {
  strings:
    $key_3258 = { 65 2a [2] 57 08 [2] 51 3d [2] 7f 3d [2] 40 21 }

  condition:
    any of them
}