rule TTP_XOR_WriteProcessMemory_3131 {
  strings:
    $key_3131 = { 66 43 [2] 54 61 [2] 52 54 [2] 7c 54 [2] 43 48 }

  condition:
    any of them
}