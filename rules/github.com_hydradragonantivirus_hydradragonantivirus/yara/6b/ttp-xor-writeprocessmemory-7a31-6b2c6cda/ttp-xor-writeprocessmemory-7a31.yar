rule TTP_XOR_WriteProcessMemory_7a31 {
  strings:
    $key_7a31 = { 2d 43 [2] 1f 61 [2] 19 54 [2] 37 54 [2] 08 48 }

  condition:
    any of them
}