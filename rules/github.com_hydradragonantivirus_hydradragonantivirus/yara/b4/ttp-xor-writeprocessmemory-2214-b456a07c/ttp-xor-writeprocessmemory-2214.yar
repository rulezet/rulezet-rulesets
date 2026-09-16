rule TTP_XOR_WriteProcessMemory_2214 {
  strings:
    $key_2214 = { 75 66 [2] 47 44 [2] 41 71 [2] 6f 71 [2] 50 6d }

  condition:
    any of them
}