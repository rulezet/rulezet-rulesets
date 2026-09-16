rule TTP_XOR_WriteProcessMemory_7a24 {
  strings:
    $key_7a24 = { 2d 56 [2] 1f 74 [2] 19 41 [2] 37 41 [2] 08 5d }

  condition:
    any of them
}