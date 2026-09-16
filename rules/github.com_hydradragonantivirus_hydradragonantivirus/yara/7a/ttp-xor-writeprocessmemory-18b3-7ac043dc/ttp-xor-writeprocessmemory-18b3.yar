rule TTP_XOR_WriteProcessMemory_18b3 {
  strings:
    $key_18b3 = { 4f c1 [2] 7d e3 [2] 7b d6 [2] 55 d6 [2] 6a ca }

  condition:
    any of them
}