rule TTP_XOR_WriteProcessMemory_1958 {
  strings:
    $key_1958 = { 4e 2a [2] 7c 08 [2] 7a 3d [2] 54 3d [2] 6b 21 }

  condition:
    any of them
}