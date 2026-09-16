rule TTP_XOR_WriteProcessMemory_da54 {
  strings:
    $key_da54 = { 8d 26 [2] bf 04 [2] b9 31 [2] 97 31 [2] a8 2d }

  condition:
    any of them
}