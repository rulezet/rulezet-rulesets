rule TTP_XOR_WriteProcessMemory_7013 {
  strings:
    $key_7013 = { 27 61 [2] 15 43 [2] 13 76 [2] 3d 76 [2] 02 6a }

  condition:
    any of them
}