rule TTP_XOR_WriteProcessMemory_ff01 {
  strings:
    $key_ff01 = { a8 73 [2] 9a 51 [2] 9c 64 [2] b2 64 [2] 8d 78 }

  condition:
    any of them
}