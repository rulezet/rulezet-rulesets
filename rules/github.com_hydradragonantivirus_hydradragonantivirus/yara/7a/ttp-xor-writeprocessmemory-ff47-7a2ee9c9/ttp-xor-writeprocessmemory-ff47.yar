rule TTP_XOR_WriteProcessMemory_ff47 {
  strings:
    $key_ff47 = { a8 35 [2] 9a 17 [2] 9c 22 [2] b2 22 [2] 8d 3e }

  condition:
    any of them
}