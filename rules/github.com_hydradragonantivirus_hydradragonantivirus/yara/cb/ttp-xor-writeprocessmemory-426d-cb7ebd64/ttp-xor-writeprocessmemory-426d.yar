rule TTP_XOR_WriteProcessMemory_426d {
  strings:
    $key_426d = { 15 1f [2] 27 3d [2] 21 08 [2] 0f 08 [2] 30 14 }

  condition:
    any of them
}