rule TTP_XOR_WriteProcessMemory_1639 {
  strings:
    $key_1639 = { 41 4b [2] 73 69 [2] 75 5c [2] 5b 5c [2] 64 40 }

  condition:
    any of them
}