rule TTP_XOR_WriteProcessMemory_1e14 {
  strings:
    $key_1e14 = { 49 66 [2] 7b 44 [2] 7d 71 [2] 53 71 [2] 6c 6d }

  condition:
    any of them
}