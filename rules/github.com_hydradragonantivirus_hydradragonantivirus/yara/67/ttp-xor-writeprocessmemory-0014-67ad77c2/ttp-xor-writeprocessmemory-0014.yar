rule TTP_XOR_WriteProcessMemory_0014 {
  strings:
    $key_0014 = { 57 66 [2] 65 44 [2] 63 71 [2] 4d 71 [2] 72 6d }

  condition:
    any of them
}