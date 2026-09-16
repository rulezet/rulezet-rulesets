rule TTP_XOR_WriteProcessMemory_4ea3 {
  strings:
    $key_4ea3 = { 19 d1 [2] 2b f3 [2] 2d c6 [2] 03 c6 [2] 3c da }

  condition:
    any of them
}