rule TTP_XOR_WriteProcessMemory_7a23 {
  strings:
    $key_7a23 = { 2d 51 [2] 1f 73 [2] 19 46 [2] 37 46 [2] 08 5a }

  condition:
    any of them
}