rule TTP_XOR_WriteProcessMemory_7694 {
  strings:
    $key_7694 = { 21 e6 [2] 13 c4 [2] 15 f1 [2] 3b f1 [2] 04 ed }

  condition:
    any of them
}