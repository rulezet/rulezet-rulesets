rule TTP_XOR_WriteProcessMemory_3d28 {
  strings:
    $key_3d28 = { 6a 5a [2] 58 78 [2] 5e 4d [2] 70 4d [2] 4f 51 }

  condition:
    any of them
}