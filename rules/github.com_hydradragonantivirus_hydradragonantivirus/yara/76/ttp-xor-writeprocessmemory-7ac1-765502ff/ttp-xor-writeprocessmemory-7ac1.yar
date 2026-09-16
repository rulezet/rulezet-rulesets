rule TTP_XOR_WriteProcessMemory_7ac1 {
  strings:
    $key_7ac1 = { 2d b3 [2] 1f 91 [2] 19 a4 [2] 37 a4 [2] 08 b8 }

  condition:
    any of them
}