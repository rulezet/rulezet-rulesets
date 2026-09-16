rule TTP_XOR_WriteProcessMemory_108c {
  strings:
    $key_108c = { 47 fe [2] 75 dc [2] 73 e9 [2] 5d e9 [2] 62 f5 }

  condition:
    any of them
}