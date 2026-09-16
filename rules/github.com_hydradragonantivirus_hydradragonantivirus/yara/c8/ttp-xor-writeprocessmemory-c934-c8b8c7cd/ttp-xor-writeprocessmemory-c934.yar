rule TTP_XOR_WriteProcessMemory_c934 {
  strings:
    $key_c934 = { 9e 46 [2] ac 64 [2] aa 51 [2] 84 51 [2] bb 4d }

  condition:
    any of them
}