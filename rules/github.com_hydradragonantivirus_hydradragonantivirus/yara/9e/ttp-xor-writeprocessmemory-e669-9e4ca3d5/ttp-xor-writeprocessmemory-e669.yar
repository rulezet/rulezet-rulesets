rule TTP_XOR_WriteProcessMemory_e669 {
  strings:
    $key_e669 = { b1 1b [2] 83 39 [2] 85 0c [2] ab 0c [2] 94 10 }

  condition:
    any of them
}