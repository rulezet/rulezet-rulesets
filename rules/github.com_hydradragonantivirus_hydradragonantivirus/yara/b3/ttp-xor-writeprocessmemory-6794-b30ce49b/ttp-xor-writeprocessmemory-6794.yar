rule TTP_XOR_WriteProcessMemory_6794 {
  strings:
    $key_6794 = { 30 e6 [2] 02 c4 [2] 04 f1 [2] 2a f1 [2] 15 ed }

  condition:
    any of them
}