rule TTP_XOR_WriteProcessMemory_0a14 {
  strings:
    $key_0a14 = { 5d 66 [2] 6f 44 [2] 69 71 [2] 47 71 [2] 78 6d }

  condition:
    any of them
}