rule TTP_XOR_WriteProcessMemory_3019 {
  strings:
    $key_3019 = { 67 6b [2] 55 49 [2] 53 7c [2] 7d 7c [2] 42 60 }

  condition:
    any of them
}