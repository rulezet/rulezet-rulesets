rule TTP_XOR_WriteProcessMemory_7719 {
  strings:
    $key_7719 = { 20 6b [2] 12 49 [2] 14 7c [2] 3a 7c [2] 05 60 }

  condition:
    any of them
}