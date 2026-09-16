rule TTP_XOR_WriteProcessMemory_f540 {
  strings:
    $key_f540 = { a2 32 [2] 90 10 [2] 96 25 [2] b8 25 [2] 87 39 }

  condition:
    any of them
}