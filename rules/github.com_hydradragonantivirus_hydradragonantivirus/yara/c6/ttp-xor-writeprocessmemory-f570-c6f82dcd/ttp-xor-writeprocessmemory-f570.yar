rule TTP_XOR_WriteProcessMemory_f570 {
  strings:
    $key_f570 = { a2 02 [2] 90 20 [2] 96 15 [2] b8 15 [2] 87 09 }

  condition:
    any of them
}