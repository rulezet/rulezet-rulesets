rule TTP_XOR_WriteProcessMemory_7a47 {
  strings:
    $key_7a47 = { 2d 35 [2] 1f 17 [2] 19 22 [2] 37 22 [2] 08 3e }

  condition:
    any of them
}