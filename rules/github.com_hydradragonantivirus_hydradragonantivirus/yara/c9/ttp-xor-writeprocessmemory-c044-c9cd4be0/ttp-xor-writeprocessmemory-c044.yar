rule TTP_XOR_WriteProcessMemory_c044 {
  strings:
    $key_c044 = { 97 36 [2] a5 14 [2] a3 21 [2] 8d 21 [2] b2 3d }

  condition:
    any of them
}