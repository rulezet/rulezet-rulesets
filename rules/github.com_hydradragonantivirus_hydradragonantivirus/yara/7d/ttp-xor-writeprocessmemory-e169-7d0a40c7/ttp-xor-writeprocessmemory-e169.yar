rule TTP_XOR_WriteProcessMemory_e169 {
  strings:
    $key_e169 = { b6 1b [2] 84 39 [2] 82 0c [2] ac 0c [2] 93 10 }

  condition:
    any of them
}