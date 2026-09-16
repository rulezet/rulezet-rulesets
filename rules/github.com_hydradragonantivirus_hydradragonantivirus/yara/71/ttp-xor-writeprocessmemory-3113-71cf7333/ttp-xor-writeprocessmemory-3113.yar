rule TTP_XOR_WriteProcessMemory_3113 {
  strings:
    $key_3113 = { 66 61 [2] 54 43 [2] 52 76 [2] 7c 76 [2] 43 6a }

  condition:
    any of them
}