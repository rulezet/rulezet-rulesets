rule TTP_XOR_WriteProcessMemory_5686 {
  strings:
    $key_5686 = { 01 f4 [2] 33 d6 [2] 35 e3 [2] 1b e3 [2] 24 ff }

  condition:
    any of them
}