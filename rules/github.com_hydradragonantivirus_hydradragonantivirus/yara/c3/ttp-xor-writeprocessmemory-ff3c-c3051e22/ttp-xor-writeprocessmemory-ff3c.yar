rule TTP_XOR_WriteProcessMemory_ff3c {
  strings:
    $key_ff3c = { a8 4e [2] 9a 6c [2] 9c 59 [2] b2 59 [2] 8d 45 }

  condition:
    any of them
}