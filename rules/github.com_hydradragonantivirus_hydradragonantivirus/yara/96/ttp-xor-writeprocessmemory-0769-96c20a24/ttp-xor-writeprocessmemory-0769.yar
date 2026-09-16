rule TTP_XOR_WriteProcessMemory_0769 {
  strings:
    $key_0769 = { 50 1b [2] 62 39 [2] 64 0c [2] 4a 0c [2] 75 10 }

  condition:
    any of them
}