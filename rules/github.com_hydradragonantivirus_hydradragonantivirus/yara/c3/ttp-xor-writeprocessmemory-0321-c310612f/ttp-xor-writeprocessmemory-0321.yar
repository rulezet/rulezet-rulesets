rule TTP_XOR_WriteProcessMemory_0321 {
  strings:
    $key_0321 = { 54 53 [2] 66 71 [2] 60 44 [2] 4e 44 [2] 71 58 }

  condition:
    any of them
}