rule TTP_XOR_WriteProcessMemory_7ad5 {
  strings:
    $key_7ad5 = { 2d a7 [2] 1f 85 [2] 19 b0 [2] 37 b0 [2] 08 ac }

  condition:
    any of them
}