rule TTP_XOR_WriteProcessMemory_2b14 {
  strings:
    $key_2b14 = { 7c 66 [2] 4e 44 [2] 48 71 [2] 66 71 [2] 59 6d }

  condition:
    any of them
}