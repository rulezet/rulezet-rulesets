rule TTP_XOR_WriteProcessMemory_308b {
  strings:
    $key_308b = { 67 f9 [2] 55 db [2] 53 ee [2] 7d ee [2] 42 f2 }

  condition:
    any of them
}