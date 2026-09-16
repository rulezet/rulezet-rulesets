rule TTP_XOR_WriteProcessMemory_f539 {
  strings:
    $key_f539 = { a2 4b [2] 90 69 [2] 96 5c [2] b8 5c [2] 87 40 }

  condition:
    any of them
}