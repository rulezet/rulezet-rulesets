rule TTP_XOR_WriteProcessMemory_3173 {
  strings:
    $key_3173 = { 66 01 [2] 54 23 [2] 52 16 [2] 7c 16 [2] 43 0a }

  condition:
    any of them
}