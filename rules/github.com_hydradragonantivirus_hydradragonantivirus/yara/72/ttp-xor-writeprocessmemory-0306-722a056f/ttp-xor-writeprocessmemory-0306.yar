rule TTP_XOR_WriteProcessMemory_0306 {
  strings:
    $key_0306 = { 54 74 [2] 66 56 [2] 60 63 [2] 4e 63 [2] 71 7f }

  condition:
    any of them
}