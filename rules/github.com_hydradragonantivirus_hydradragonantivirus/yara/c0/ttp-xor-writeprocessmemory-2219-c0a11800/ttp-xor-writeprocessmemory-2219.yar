rule TTP_XOR_WriteProcessMemory_2219 {
  strings:
    $key_2219 = { 75 6b [2] 47 49 [2] 41 7c [2] 6f 7c [2] 50 60 }

  condition:
    any of them
}