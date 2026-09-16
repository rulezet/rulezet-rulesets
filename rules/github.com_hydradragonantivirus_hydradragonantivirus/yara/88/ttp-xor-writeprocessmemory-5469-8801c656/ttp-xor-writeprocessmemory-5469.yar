rule TTP_XOR_WriteProcessMemory_5469 {
  strings:
    $key_5469 = { 03 1b [2] 31 39 [2] 37 0c [2] 19 0c [2] 26 10 }

  condition:
    any of them
}