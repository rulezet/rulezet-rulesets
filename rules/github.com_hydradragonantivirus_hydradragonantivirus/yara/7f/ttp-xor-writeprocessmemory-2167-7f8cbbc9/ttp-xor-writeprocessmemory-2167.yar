rule TTP_XOR_WriteProcessMemory_2167 {
  strings:
    $key_2167 = { 76 15 [2] 44 37 [2] 42 02 [2] 6c 02 [2] 53 1e }

  condition:
    any of them
}