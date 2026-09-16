rule TTP_XOR_WriteProcessMemory_0719 {
  strings:
    $key_0719 = { 50 6b [2] 62 49 [2] 64 7c [2] 4a 7c [2] 75 60 }

  condition:
    any of them
}