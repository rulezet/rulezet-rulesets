rule TTP_XOR_WriteProcessMemory_5a19 {
  strings:
    $key_5a19 = { 0d 6b [2] 3f 49 [2] 39 7c [2] 17 7c [2] 28 60 }

  condition:
    any of them
}