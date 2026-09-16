rule TTP_XOR_WriteProcessMemory_5d54 {
  strings:
    $key_5d54 = { 0a 26 [2] 38 04 [2] 3e 31 [2] 10 31 [2] 2f 2d }

  condition:
    any of them
}