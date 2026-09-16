rule TTP_XOR_WriteProcessMemory_0777 {
  strings:
    $key_0777 = { 50 05 [2] 62 27 [2] 64 12 [2] 4a 12 [2] 75 0e }

  condition:
    any of them
}