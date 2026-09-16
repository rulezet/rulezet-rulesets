rule TTP_XOR_WriteProcessMemory_316d {
  strings:
    $key_316d = { 66 1f [2] 54 3d [2] 52 08 [2] 7c 08 [2] 43 14 }

  condition:
    any of them
}