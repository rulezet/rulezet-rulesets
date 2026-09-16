rule TTP_XOR_WriteProcessMemory_38b3 {
  strings:
    $key_38b3 = { 6f c1 [2] 5d e3 [2] 5b d6 [2] 75 d6 [2] 4a ca }

  condition:
    any of them
}