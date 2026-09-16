rule TTP_XOR_WriteProcessMemory_f559 {
  strings:
    $key_f559 = { a2 2b [2] 90 09 [2] 96 3c [2] b8 3c [2] 87 20 }

  condition:
    any of them
}