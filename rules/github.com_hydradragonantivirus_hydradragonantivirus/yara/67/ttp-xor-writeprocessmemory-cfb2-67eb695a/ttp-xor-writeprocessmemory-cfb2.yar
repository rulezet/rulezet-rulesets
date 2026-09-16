rule TTP_XOR_WriteProcessMemory_cfb2 {
  strings:
    $key_cfb2 = { 98 c0 [2] aa e2 [2] ac d7 [2] 82 d7 [2] bd cb }

  condition:
    any of them
}