rule TTP_XOR_WriteProcessMemory_5bb3 {
  strings:
    $key_5bb3 = { 0c c1 [2] 3e e3 [2] 38 d6 [2] 16 d6 [2] 29 ca }

  condition:
    any of them
}