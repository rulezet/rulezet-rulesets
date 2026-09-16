rule TTP_XOR_WriteProcessMemory_3844 {
  strings:
    $key_3844 = { 6f 36 [2] 5d 14 [2] 5b 21 [2] 75 21 [2] 4a 3d }

  condition:
    any of them
}