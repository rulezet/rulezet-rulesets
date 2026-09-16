rule TTP_XOR_WriteProcessMemory_6a45 {
  strings:
    $key_6a45 = { 3d 37 [2] 0f 15 [2] 09 20 [2] 27 20 [2] 18 3c }

  condition:
    any of them
}