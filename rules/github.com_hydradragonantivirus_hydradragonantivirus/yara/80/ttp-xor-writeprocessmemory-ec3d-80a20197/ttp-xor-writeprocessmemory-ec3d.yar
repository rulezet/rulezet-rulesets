rule TTP_XOR_WriteProcessMemory_ec3d {
  strings:
    $key_ec3d = { bb 4f [2] 89 6d [2] 8f 58 [2] a1 58 [2] 9e 44 }

  condition:
    any of them
}