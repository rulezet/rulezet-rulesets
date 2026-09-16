rule TTP_XOR_WriteProcessMemory_0339 {
  strings:
    $key_0339 = { 54 4b [2] 66 69 [2] 60 5c [2] 4e 5c [2] 71 40 }

  condition:
    any of them
}