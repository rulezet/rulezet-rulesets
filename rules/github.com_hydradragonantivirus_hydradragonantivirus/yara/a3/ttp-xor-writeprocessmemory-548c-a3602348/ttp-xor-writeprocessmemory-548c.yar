rule TTP_XOR_WriteProcessMemory_548c {
  strings:
    $key_548c = { 03 fe [2] 31 dc [2] 37 e9 [2] 19 e9 [2] 26 f5 }

  condition:
    any of them
}