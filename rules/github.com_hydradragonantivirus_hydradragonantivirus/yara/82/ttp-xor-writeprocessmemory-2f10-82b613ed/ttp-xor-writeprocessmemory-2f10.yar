rule TTP_XOR_WriteProcessMemory_2f10 {
  strings:
    $key_2f10 = { 78 62 [2] 4a 40 [2] 4c 75 [2] 62 75 [2] 5d 69 }

  condition:
    any of them
}