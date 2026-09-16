rule TTP_XOR_WriteProcessMemory_2444 {
  strings:
    $key_2444 = { 73 36 [2] 41 14 [2] 47 21 [2] 69 21 [2] 56 3d }

  condition:
    any of them
}