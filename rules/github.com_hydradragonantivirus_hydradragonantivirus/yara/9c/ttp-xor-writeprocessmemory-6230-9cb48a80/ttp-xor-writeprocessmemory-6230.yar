rule TTP_XOR_WriteProcessMemory_6230 {
  strings:
    $key_6230 = { 35 42 [2] 07 60 [2] 01 55 [2] 2f 55 [2] 10 49 }

  condition:
    any of them
}