rule TTP_XOR_WriteProcessMemory_a309 {
  strings:
    $key_a309 = { f4 7b [2] c6 59 [2] c0 6c [2] ee 6c [2] d1 70 }

  condition:
    any of them
}