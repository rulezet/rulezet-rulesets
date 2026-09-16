rule TTP_XOR_WriteProcessMemory_7a13 {
  strings:
    $key_7a13 = { 2d 61 [2] 1f 43 [2] 19 76 [2] 37 76 [2] 08 6a }

  condition:
    any of them
}