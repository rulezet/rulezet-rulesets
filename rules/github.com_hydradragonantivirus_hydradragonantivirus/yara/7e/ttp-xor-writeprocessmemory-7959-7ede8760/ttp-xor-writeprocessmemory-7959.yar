rule TTP_XOR_WriteProcessMemory_7959 {
  strings:
    $key_7959 = { 2e 2b [2] 1c 09 [2] 1a 3c [2] 34 3c [2] 0b 20 }

  condition:
    any of them
}