rule TTP_XOR_WriteProcessMemory_6c69 {
  strings:
    $key_6c69 = { 3b 1b [2] 09 39 [2] 0f 0c [2] 21 0c [2] 1e 10 }

  condition:
    any of them
}