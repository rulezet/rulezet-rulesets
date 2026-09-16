rule TTP_XOR_WriteProcessMemory_6286 {
  strings:
    $key_6286 = { 35 f4 [2] 07 d6 [2] 01 e3 [2] 2f e3 [2] 10 ff }

  condition:
    any of them
}