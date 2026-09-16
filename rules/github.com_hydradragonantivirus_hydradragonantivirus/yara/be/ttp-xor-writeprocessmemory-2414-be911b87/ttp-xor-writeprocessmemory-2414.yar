rule TTP_XOR_WriteProcessMemory_2414 {
  strings:
    $key_2414 = { 73 66 [2] 41 44 [2] 47 71 [2] 69 71 [2] 56 6d }

  condition:
    any of them
}