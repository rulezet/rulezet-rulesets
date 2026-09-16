rule TTP_XOR_WriteProcessMemory_3170 {
  strings:
    $key_3170 = { 66 02 [2] 54 20 [2] 52 15 [2] 7c 15 [2] 43 09 }

  condition:
    any of them
}