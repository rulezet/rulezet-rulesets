rule TTP_XOR_WriteProcessMemory_6aa9 {
  strings:
    $key_6aa9 = { 3d db [2] 0f f9 [2] 09 cc [2] 27 cc [2] 18 d0 }

  condition:
    any of them
}