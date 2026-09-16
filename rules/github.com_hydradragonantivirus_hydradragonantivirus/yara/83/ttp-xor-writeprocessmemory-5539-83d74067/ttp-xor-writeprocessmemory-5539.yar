rule TTP_XOR_WriteProcessMemory_5539 {
  strings:
    $key_5539 = { 02 4b [2] 30 69 [2] 36 5c [2] 18 5c [2] 27 40 }

  condition:
    any of them
}