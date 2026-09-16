rule TTP_XOR_WriteProcessMemory_6217 {
  strings:
    $key_6217 = { 35 65 [2] 07 47 [2] 01 72 [2] 2f 72 [2] 10 6e }

  condition:
    any of them
}