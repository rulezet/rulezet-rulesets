rule TTP_XOR_WriteProcessMemory_e739 {
  strings:
    $key_e739 = { b0 4b [2] 82 69 [2] 84 5c [2] aa 5c [2] 95 40 }

  condition:
    any of them
}