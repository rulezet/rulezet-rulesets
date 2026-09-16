rule TTP_XOR_WriteProcessMemory_3b14 {
  strings:
    $key_3b14 = { 6c 66 [2] 5e 44 [2] 58 71 [2] 76 71 [2] 49 6d }

  condition:
    any of them
}