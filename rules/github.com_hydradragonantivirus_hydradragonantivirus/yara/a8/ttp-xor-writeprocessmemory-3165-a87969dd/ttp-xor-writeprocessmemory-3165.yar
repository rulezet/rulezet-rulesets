rule TTP_XOR_WriteProcessMemory_3165 {
  strings:
    $key_3165 = { 66 17 [2] 54 35 [2] 52 00 [2] 7c 00 [2] 43 1c }

  condition:
    any of them
}