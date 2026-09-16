rule TTP_XOR_WriteProcessMemory_5444 {
  strings:
    $key_5444 = { 03 36 [2] 31 14 [2] 37 21 [2] 19 21 [2] 26 3d }

  condition:
    any of them
}