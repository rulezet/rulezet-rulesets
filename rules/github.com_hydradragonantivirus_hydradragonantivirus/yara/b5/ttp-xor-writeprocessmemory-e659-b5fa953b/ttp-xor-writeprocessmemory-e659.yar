rule TTP_XOR_WriteProcessMemory_e659 {
  strings:
    $key_e659 = { b1 2b [2] 83 09 [2] 85 3c [2] ab 3c [2] 94 20 }

  condition:
    any of them
}