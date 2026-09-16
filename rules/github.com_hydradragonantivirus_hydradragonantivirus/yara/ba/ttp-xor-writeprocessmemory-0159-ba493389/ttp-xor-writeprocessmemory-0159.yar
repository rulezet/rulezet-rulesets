rule TTP_XOR_WriteProcessMemory_0159 {
  strings:
    $key_0159 = { 56 2b [2] 64 09 [2] 62 3c [2] 4c 3c [2] 73 20 }

  condition:
    any of them
}