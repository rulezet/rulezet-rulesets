rule TTP_XOR_WriteProcessMemory_0333 {
  strings:
    $key_0333 = { 54 41 [2] 66 63 [2] 60 56 [2] 4e 56 [2] 71 4a }

  condition:
    any of them
}