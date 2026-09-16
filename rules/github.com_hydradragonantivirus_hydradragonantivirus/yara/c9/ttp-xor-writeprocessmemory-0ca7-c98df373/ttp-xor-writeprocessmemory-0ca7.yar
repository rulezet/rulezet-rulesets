rule TTP_XOR_WriteProcessMemory_0ca7 {
  strings:
    $key_0ca7 = { 5b d5 [2] 69 f7 [2] 6f c2 [2] 41 c2 [2] 7e de }

  condition:
    any of them
}