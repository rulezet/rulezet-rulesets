rule TTP_XOR_WriteProcessMemory_0f97 {
  strings:
    $key_0f97 = { 58 e5 [2] 6a c7 [2] 6c f2 [2] 42 f2 [2] 7d ee }

  condition:
    any of them
}