rule TTP_XOR_WriteProcessMemory_c614 {
  strings:
    $key_c614 = { 91 66 [2] a3 44 [2] a5 71 [2] 8b 71 [2] b4 6d }

  condition:
    any of them
}