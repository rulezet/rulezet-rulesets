rule TTP_XOR_WriteProcessMemory_7c19 {
  strings:
    $key_7c19 = { 2b 6b [2] 19 49 [2] 1f 7c [2] 31 7c [2] 0e 60 }

  condition:
    any of them
}