rule TTP_XOR_WriteProcessMemory_e769 {
  strings:
    $key_e769 = { b0 1b [2] 82 39 [2] 84 0c [2] aa 0c [2] 95 10 }

  condition:
    any of them
}