rule TTP_XOR_WriteProcessMemory_0639 {
  strings:
    $key_0639 = { 51 4b [2] 63 69 [2] 65 5c [2] 4b 5c [2] 74 40 }

  condition:
    any of them
}