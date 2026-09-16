rule TTP_XOR_WriteProcessMemory_2958 {
  strings:
    $key_2958 = { 7e 2a [2] 4c 08 [2] 4a 3d [2] 64 3d [2] 5b 21 }

  condition:
    any of them
}