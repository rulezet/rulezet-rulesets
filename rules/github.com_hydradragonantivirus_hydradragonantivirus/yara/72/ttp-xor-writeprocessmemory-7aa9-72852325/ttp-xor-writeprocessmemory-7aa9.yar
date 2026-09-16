rule TTP_XOR_WriteProcessMemory_7aa9 {
  strings:
    $key_7aa9 = { 2d db [2] 1f f9 [2] 19 cc [2] 37 cc [2] 08 d0 }

  condition:
    any of them
}