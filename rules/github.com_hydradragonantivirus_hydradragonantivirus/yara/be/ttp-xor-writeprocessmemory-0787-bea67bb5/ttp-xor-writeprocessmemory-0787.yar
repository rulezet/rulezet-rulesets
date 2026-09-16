rule TTP_XOR_WriteProcessMemory_0787 {
  strings:
    $key_0787 = { 50 f5 [2] 62 d7 [2] 64 e2 [2] 4a e2 [2] 75 fe }

  condition:
    any of them
}