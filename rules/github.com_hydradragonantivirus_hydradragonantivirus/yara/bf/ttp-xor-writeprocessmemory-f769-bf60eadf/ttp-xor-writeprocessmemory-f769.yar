rule TTP_XOR_WriteProcessMemory_f769 {
  strings:
    $key_f769 = { a0 1b [2] 92 39 [2] 94 0c [2] ba 0c [2] 85 10 }

  condition:
    any of them
}