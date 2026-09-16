rule TTP_XOR_WriteProcessMemory_06f9 {
  strings:
    $key_06f9 = { 51 8b [2] 63 a9 [2] 65 9c [2] 4b 9c [2] 74 80 }

  condition:
    any of them
}