rule TTP_XOR_WriteProcessMemory_16a2 {
  strings:
    $key_16a2 = { 41 d0 [2] 73 f2 [2] 75 c7 [2] 5b c7 [2] 64 db }

  condition:
    any of them
}