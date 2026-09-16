rule TTP_XOR_WriteProcessMemory_f842 {
  strings:
    $key_f842 = { af 30 [2] 9d 12 [2] 9b 27 [2] b5 27 [2] 8a 3b }

  condition:
    any of them
}