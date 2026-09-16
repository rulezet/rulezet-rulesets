rule TTP_XOR_WriteProcessMemory_6769 {
  strings:
    $key_6769 = { 30 1b [2] 02 39 [2] 04 0c [2] 2a 0c [2] 15 10 }

  condition:
    any of them
}