rule TTP_XOR_WriteProcessMemory_8469 {
  strings:
    $key_8469 = { d3 1b [2] e1 39 [2] e7 0c [2] c9 0c [2] f6 10 }

  condition:
    any of them
}