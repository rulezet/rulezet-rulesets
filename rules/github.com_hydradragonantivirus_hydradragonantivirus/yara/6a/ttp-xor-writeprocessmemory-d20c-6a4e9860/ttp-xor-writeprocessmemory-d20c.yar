rule TTP_XOR_WriteProcessMemory_d20c {
  strings:
    $key_d20c = { 85 7e [2] b7 5c [2] b1 69 [2] 9f 69 [2] a0 75 }

  condition:
    any of them
}