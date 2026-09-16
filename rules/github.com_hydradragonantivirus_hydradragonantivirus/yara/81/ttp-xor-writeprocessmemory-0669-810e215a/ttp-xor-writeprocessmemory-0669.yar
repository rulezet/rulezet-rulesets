rule TTP_XOR_WriteProcessMemory_0669 {
  strings:
    $key_0669 = { 51 1b [2] 63 39 [2] 65 0c [2] 4b 0c [2] 74 10 }

  condition:
    any of them
}