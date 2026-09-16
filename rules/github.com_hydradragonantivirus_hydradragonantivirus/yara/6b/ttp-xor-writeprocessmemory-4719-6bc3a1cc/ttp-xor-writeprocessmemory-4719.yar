rule TTP_XOR_WriteProcessMemory_4719 {
  strings:
    $key_4719 = { 10 6b [2] 22 49 [2] 24 7c [2] 0a 7c [2] 35 60 }

  condition:
    any of them
}