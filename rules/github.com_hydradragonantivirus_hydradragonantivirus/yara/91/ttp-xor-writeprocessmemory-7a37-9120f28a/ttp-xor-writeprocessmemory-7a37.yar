rule TTP_XOR_WriteProcessMemory_7a37 {
  strings:
    $key_7a37 = { 2d 45 [2] 1f 67 [2] 19 52 [2] 37 52 [2] 08 4e }

  condition:
    any of them
}