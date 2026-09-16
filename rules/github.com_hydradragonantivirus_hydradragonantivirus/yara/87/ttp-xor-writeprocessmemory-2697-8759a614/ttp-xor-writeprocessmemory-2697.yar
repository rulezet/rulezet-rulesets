rule TTP_XOR_WriteProcessMemory_2697 {
  strings:
    $key_2697 = { 71 e5 [2] 43 c7 [2] 45 f2 [2] 6b f2 [2] 54 ee }

  condition:
    any of them
}