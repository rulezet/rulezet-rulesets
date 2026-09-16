rule TTP_XOR_WriteProcessMemory_2152 {
  strings:
    $key_2152 = { 76 20 [2] 44 02 [2] 42 37 [2] 6c 37 [2] 53 2b }

  condition:
    any of them
}