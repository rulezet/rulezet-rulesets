rule TTP_XOR_WriteProcessMemory_0d39 {
  strings:
    $key_0d39 = { 5a 4b [2] 68 69 [2] 6e 5c [2] 40 5c [2] 7f 40 }

  condition:
    any of them
}