rule TTP_XOR_WriteProcessMemory_7a77 {
  strings:
    $key_7a77 = { 2d 05 [2] 1f 27 [2] 19 12 [2] 37 12 [2] 08 0e }

  condition:
    any of them
}