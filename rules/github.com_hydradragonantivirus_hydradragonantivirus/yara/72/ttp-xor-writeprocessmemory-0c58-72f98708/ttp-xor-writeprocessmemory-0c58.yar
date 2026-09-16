rule TTP_XOR_WriteProcessMemory_0c58 {
  strings:
    $key_0c58 = { 5b 2a [2] 69 08 [2] 6f 3d [2] 41 3d [2] 7e 21 }

  condition:
    any of them
}