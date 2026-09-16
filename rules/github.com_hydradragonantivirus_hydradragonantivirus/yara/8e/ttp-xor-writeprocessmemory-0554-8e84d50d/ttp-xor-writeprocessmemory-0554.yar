rule TTP_XOR_WriteProcessMemory_0554 {
  strings:
    $key_0554 = { 52 26 [2] 60 04 [2] 66 31 [2] 48 31 [2] 77 2d }

  condition:
    any of them
}