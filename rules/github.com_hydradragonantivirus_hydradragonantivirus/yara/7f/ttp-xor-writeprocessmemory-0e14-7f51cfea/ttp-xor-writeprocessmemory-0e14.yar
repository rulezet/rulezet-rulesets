rule TTP_XOR_WriteProcessMemory_0e14 {
  strings:
    $key_0e14 = { 59 66 [2] 6b 44 [2] 6d 71 [2] 43 71 [2] 7c 6d }

  condition:
    any of them
}