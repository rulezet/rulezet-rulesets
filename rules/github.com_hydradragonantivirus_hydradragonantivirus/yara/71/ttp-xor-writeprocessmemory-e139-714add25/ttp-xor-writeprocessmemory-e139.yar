rule TTP_XOR_WriteProcessMemory_e139 {
  strings:
    $key_e139 = { b6 4b [2] 84 69 [2] 82 5c [2] ac 5c [2] 93 40 }

  condition:
    any of them
}