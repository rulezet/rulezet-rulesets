rule TTP_XOR_WriteProcessMemory_6494 {
  strings:
    $key_6494 = { 33 e6 [2] 01 c4 [2] 07 f1 [2] 29 f1 [2] 16 ed }

  condition:
    any of them
}