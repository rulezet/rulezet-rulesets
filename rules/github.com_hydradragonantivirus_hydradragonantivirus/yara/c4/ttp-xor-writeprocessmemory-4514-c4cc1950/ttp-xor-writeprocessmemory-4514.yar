rule TTP_XOR_WriteProcessMemory_4514 {
  strings:
    $key_4514 = { 12 66 [2] 20 44 [2] 26 71 [2] 08 71 [2] 37 6d }

  condition:
    any of them
}