rule TTP_XOR_WriteProcessMemory_0511 {
  strings:
    $key_0511 = { 52 63 [2] 60 41 [2] 66 74 [2] 48 74 [2] 77 68 }

  condition:
    any of them
}