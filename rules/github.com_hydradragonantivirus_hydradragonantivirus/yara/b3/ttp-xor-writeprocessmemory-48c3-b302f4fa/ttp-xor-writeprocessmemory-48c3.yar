rule TTP_XOR_WriteProcessMemory_48c3 {
  strings:
    $key_48c3 = { 1f b1 [2] 2d 93 [2] 2b a6 [2] 05 a6 [2] 3a ba }

  condition:
    any of them
}