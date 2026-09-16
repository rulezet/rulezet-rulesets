rule TTP_XOR_WriteProcessMemory_26b3 {
  strings:
    $key_26b3 = { 71 c1 [2] 43 e3 [2] 45 d6 [2] 6b d6 [2] 54 ca }

  condition:
    any of them
}