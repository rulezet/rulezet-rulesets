rule TTP_XOR_WriteProcessMemory_5214 {
  strings:
    $key_5214 = { 05 66 [2] 37 44 [2] 31 71 [2] 1f 71 [2] 20 6d }

  condition:
    any of them
}