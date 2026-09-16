rule TTP_XOR_WriteProcessMemory_3130 {
  strings:
    $key_3130 = { 66 42 [2] 54 60 [2] 52 55 [2] 7c 55 [2] 43 49 }

  condition:
    any of them
}