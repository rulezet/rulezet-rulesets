rule TTP_XOR_WriteProcessMemory_0682 {
  strings:
    $key_0682 = { 51 f0 [2] 63 d2 [2] 65 e7 [2] 4b e7 [2] 74 fb }

  condition:
    any of them
}