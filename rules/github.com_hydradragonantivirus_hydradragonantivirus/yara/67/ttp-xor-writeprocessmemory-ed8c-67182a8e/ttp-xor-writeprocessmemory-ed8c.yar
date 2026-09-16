rule TTP_XOR_WriteProcessMemory_ed8c {
  strings:
    $key_ed8c = { ba fe [2] 88 dc [2] 8e e9 [2] a0 e9 [2] 9f f5 }

  condition:
    any of them
}