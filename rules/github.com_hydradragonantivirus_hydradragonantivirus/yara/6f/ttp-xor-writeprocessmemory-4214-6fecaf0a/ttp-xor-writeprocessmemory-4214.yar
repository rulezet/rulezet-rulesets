rule TTP_XOR_WriteProcessMemory_4214 {
  strings:
    $key_4214 = { 15 66 [2] 27 44 [2] 21 71 [2] 0f 71 [2] 30 6d }

  condition:
    any of them
}