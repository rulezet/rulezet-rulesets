rule TTP_XOR_WriteProcessMemory_760c {
  strings:
    $key_760c = { 21 7e [2] 13 5c [2] 15 69 [2] 3b 69 [2] 04 75 }

  condition:
    any of them
}