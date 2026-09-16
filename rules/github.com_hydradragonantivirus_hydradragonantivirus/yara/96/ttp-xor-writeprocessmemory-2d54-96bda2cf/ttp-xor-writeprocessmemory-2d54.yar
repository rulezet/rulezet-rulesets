rule TTP_XOR_WriteProcessMemory_2d54 {
  strings:
    $key_2d54 = { 7a 26 [2] 48 04 [2] 4e 31 [2] 60 31 [2] 5f 2d }

  condition:
    any of them
}