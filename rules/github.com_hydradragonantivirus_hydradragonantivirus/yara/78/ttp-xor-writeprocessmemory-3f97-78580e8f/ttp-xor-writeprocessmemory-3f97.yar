rule TTP_XOR_WriteProcessMemory_3f97 {
  strings:
    $key_3f97 = { 68 e5 [2] 5a c7 [2] 5c f2 [2] 72 f2 [2] 4d ee }

  condition:
    any of them
}