rule TTP_XOR_WriteProcessMemory_0507 {
  strings:
    $key_0507 = { 52 75 [2] 60 57 [2] 66 62 [2] 48 62 [2] 77 7e }

  condition:
    any of them
}