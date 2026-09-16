rule TTP_XOR_WriteProcessMemory_0531 {
  strings:
    $key_0531 = { 52 43 [2] 60 61 [2] 66 54 [2] 48 54 [2] 77 48 }

  condition:
    any of them
}