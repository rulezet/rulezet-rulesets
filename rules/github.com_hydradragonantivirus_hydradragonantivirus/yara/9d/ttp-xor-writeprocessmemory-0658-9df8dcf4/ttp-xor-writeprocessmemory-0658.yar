rule TTP_XOR_WriteProcessMemory_0658 {
  strings:
    $key_0658 = { 51 2a [2] 63 08 [2] 65 3d [2] 4b 3d [2] 74 21 }

  condition:
    any of them
}