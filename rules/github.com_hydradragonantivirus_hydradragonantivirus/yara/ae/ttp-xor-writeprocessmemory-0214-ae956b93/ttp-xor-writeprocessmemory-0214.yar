rule TTP_XOR_WriteProcessMemory_0214 {
  strings:
    $key_0214 = { 55 66 [2] 67 44 [2] 61 71 [2] 4f 71 [2] 70 6d }

  condition:
    any of them
}