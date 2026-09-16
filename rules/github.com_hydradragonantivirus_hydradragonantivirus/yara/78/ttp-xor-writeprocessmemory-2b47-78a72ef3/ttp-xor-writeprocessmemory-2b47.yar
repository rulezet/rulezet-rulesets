rule TTP_XOR_WriteProcessMemory_2b47 {
  strings:
    $key_2b47 = { 7c 35 [2] 4e 17 [2] 48 22 [2] 66 22 [2] 59 3e }

  condition:
    any of them
}