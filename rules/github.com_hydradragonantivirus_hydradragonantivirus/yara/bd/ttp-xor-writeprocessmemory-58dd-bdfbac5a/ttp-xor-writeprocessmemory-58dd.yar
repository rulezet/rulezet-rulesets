rule TTP_XOR_WriteProcessMemory_58dd {
  strings:
    $key_58dd = { 0f af [2] 3d 8d [2] 3b b8 [2] 15 b8 [2] 2a a4 }

  condition:
    any of them
}