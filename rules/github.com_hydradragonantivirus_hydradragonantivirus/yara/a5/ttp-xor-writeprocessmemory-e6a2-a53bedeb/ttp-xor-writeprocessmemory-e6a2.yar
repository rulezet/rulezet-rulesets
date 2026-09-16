rule TTP_XOR_WriteProcessMemory_e6a2 {
  strings:
    $key_e6a2 = { b1 d0 [2] 83 f2 [2] 85 c7 [2] ab c7 [2] 94 db }

  condition:
    any of them
}