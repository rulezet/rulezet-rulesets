rule TTP_XOR_WriteProcessMemory_1f97 {
  strings:
    $key_1f97 = { 48 e5 [2] 7a c7 [2] 7c f2 [2] 52 f2 [2] 6d ee }

  condition:
    any of them
}