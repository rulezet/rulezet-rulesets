rule TTP_XOR_WriteProcessMemory_e014 {
  strings:
    $key_e014 = { b7 66 [2] 85 44 [2] 83 71 [2] ad 71 [2] 92 6d }

  condition:
    any of them
}