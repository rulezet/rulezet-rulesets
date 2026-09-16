rule TTP_XOR_WriteProcessMemory_388c {
  strings:
    $key_388c = { 6f fe [2] 5d dc [2] 5b e9 [2] 75 e9 [2] 4a f5 }

  condition:
    any of them
}