rule TTP_XOR_WriteProcessMemory_6958 {
  strings:
    $key_6958 = { 3e 2a [2] 0c 08 [2] 0a 3d [2] 24 3d [2] 1b 21 }

  condition:
    any of them
}