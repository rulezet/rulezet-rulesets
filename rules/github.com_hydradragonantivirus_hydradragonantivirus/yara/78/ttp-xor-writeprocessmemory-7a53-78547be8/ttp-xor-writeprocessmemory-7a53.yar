rule TTP_XOR_WriteProcessMemory_7a53 {
  strings:
    $key_7a53 = { 2d 21 [2] 1f 03 [2] 19 36 [2] 37 36 [2] 08 2a }

  condition:
    any of them
}