rule TTP_XOR_WriteProcessMemory_eb58 {
  strings:
    $key_eb58 = { bc 2a [2] 8e 08 [2] 88 3d [2] a6 3d [2] 99 21 }

  condition:
    any of them
}