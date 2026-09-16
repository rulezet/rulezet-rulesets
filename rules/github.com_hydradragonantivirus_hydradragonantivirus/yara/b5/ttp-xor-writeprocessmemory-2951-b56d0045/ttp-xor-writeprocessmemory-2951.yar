rule TTP_XOR_WriteProcessMemory_2951 {
  strings:
    $key_2951 = { 7e 23 [2] 4c 01 [2] 4a 34 [2] 64 34 [2] 5b 28 }

  condition:
    any of them
}