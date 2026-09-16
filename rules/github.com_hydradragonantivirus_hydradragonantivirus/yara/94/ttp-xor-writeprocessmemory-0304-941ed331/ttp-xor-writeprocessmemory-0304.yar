rule TTP_XOR_WriteProcessMemory_0304 {
  strings:
    $key_0304 = { 54 76 [2] 66 54 [2] 60 61 [2] 4e 61 [2] 71 7d }

  condition:
    any of them
}