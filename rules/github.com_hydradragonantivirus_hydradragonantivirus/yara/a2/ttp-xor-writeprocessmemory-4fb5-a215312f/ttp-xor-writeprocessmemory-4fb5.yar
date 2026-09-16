rule TTP_XOR_WriteProcessMemory_4fb5 {
  strings:
    $key_4fb5 = { 18 c7 [2] 2a e5 [2] 2c d0 [2] 02 d0 [2] 3d cc }

  condition:
    any of them
}