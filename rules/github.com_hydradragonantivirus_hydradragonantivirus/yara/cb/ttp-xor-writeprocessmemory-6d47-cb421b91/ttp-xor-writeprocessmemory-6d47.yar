rule TTP_XOR_WriteProcessMemory_6d47 {
  strings:
    $key_6d47 = { 3a 35 [2] 08 17 [2] 0e 22 [2] 20 22 [2] 1f 3e }

  condition:
    any of them
}