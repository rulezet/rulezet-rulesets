rule TTP_XOR_WriteProcessMemory_0313 {
  strings:
    $key_0313 = { 54 61 [2] 66 43 [2] 60 76 [2] 4e 76 [2] 71 6a }

  condition:
    any of them
}