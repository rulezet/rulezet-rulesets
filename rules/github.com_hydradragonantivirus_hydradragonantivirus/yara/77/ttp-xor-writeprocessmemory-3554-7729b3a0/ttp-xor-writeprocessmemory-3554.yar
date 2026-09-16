rule TTP_XOR_WriteProcessMemory_3554 {
  strings:
    $key_3554 = { 62 26 [2] 50 04 [2] 56 31 [2] 78 31 [2] 47 2d }

  condition:
    any of them
}