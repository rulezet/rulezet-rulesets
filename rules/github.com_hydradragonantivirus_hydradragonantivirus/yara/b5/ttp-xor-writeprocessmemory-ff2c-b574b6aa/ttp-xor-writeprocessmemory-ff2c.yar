rule TTP_XOR_WriteProcessMemory_ff2c {
  strings:
    $key_ff2c = { a8 5e [2] 9a 7c [2] 9c 49 [2] b2 49 [2] 8d 55 }

  condition:
    any of them
}