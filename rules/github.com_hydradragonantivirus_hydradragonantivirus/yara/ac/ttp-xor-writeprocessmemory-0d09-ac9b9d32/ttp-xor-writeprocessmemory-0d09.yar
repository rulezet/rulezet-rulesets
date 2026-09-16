rule TTP_XOR_WriteProcessMemory_0d09 {
  strings:
    $key_0d09 = { 5a 7b [2] 68 59 [2] 6e 6c [2] 40 6c [2] 7f 70 }

  condition:
    any of them
}