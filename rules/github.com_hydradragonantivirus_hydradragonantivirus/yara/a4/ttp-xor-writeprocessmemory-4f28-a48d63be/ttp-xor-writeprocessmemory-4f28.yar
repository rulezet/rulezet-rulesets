rule TTP_XOR_WriteProcessMemory_4f28 {
  strings:
    $key_4f28 = { 18 5a [2] 2a 78 [2] 2c 4d [2] 02 4d [2] 3d 51 }

  condition:
    any of them
}