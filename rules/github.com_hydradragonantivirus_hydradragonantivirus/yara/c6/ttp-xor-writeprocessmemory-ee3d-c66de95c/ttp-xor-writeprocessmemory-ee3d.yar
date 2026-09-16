rule TTP_XOR_WriteProcessMemory_ee3d {
  strings:
    $key_ee3d = { b9 4f [2] 8b 6d [2] 8d 58 [2] a3 58 [2] 9c 44 }

  condition:
    any of them
}