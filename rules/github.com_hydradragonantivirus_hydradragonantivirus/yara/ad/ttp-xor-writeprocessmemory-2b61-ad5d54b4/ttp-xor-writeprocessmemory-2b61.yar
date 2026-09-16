rule TTP_XOR_WriteProcessMemory_2b61 {
  strings:
    $key_2b61 = { 7c 13 [2] 4e 31 [2] 48 04 [2] 66 04 [2] 59 18 }

  condition:
    any of them
}