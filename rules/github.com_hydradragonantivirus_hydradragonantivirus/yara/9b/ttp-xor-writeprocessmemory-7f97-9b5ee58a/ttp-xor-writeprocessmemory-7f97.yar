rule TTP_XOR_WriteProcessMemory_7f97 {
  strings:
    $key_7f97 = { 28 e5 [2] 1a c7 [2] 1c f2 [2] 32 f2 [2] 0d ee }

  condition:
    any of them
}