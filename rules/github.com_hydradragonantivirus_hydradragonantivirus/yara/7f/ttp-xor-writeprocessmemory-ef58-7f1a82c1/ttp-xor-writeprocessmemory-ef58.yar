rule TTP_XOR_WriteProcessMemory_ef58 {
  strings:
    $key_ef58 = { b8 2a [2] 8a 08 [2] 8c 3d [2] a2 3d [2] 9d 21 }

  condition:
    any of them
}