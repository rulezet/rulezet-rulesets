rule TTP_XOR_WriteProcessMemory_ff09 {
  strings:
    $key_ff09 = { a8 7b [2] 9a 59 [2] 9c 6c [2] b2 6c [2] 8d 70 }

  condition:
    any of them
}