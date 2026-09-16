rule TTP_XOR_WriteProcessMemory_e639 {
  strings:
    $key_e639 = { b1 4b [2] 83 69 [2] 85 5c [2] ab 5c [2] 94 40 }

  condition:
    any of them
}