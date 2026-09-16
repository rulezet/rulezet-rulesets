rule TTP_XOR_WriteProcessMemory_3958 {
  strings:
    $key_3958 = { 6e 2a [2] 5c 08 [2] 5a 3d [2] 74 3d [2] 4b 21 }

  condition:
    any of them
}