rule TTP_XOR_WriteProcessMemory_5430 {
  strings:
    $key_5430 = { 03 42 [2] 31 60 [2] 37 55 [2] 19 55 [2] 26 49 }

  condition:
    any of them
}