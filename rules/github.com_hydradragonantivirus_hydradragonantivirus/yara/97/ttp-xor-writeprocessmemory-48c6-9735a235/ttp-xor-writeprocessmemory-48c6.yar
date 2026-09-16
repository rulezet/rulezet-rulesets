rule TTP_XOR_WriteProcessMemory_48c6 {
  strings:
    $key_48c6 = { 1f b4 [2] 2d 96 [2] 2b a3 [2] 05 a3 [2] 3a bf }

  condition:
    any of them
}