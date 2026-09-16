rule TTP_XOR_WriteProcessMemory_2b13 {
  strings:
    $key_2b13 = { 7c 61 [2] 4e 43 [2] 48 76 [2] 66 76 [2] 59 6a }

  condition:
    any of them
}