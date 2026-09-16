rule TTP_XOR_WriteProcessMemory_0629 {
  strings:
    $key_0629 = { 51 5b [2] 63 79 [2] 65 4c [2] 4b 4c [2] 74 50 }

  condition:
    any of them
}