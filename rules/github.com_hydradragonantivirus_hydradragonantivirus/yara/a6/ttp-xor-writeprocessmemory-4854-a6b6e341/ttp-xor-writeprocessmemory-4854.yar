rule TTP_XOR_WriteProcessMemory_4854 {
  strings:
    $key_4854 = { 1f 26 [2] 2d 04 [2] 2b 31 [2] 05 31 [2] 3a 2d }

  condition:
    any of them
}