rule TTP_XOR_WriteProcessMemory_3854 {
  strings:
    $key_3854 = { 6f 26 [2] 5d 04 [2] 5b 31 [2] 75 31 [2] 4a 2d }

  condition:
    any of them
}