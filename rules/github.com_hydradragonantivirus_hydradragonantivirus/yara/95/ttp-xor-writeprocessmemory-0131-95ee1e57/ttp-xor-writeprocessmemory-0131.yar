rule TTP_XOR_WriteProcessMemory_0131 {
  strings:
    $key_0131 = { 56 43 [2] 64 61 [2] 62 54 [2] 4c 54 [2] 73 48 }

  condition:
    any of them
}