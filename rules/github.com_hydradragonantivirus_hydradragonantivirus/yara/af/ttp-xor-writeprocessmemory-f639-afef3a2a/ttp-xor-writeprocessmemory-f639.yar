rule TTP_XOR_WriteProcessMemory_f639 {
  strings:
    $key_f639 = { a1 4b [2] 93 69 [2] 95 5c [2] bb 5c [2] 84 40 }

  condition:
    any of them
}