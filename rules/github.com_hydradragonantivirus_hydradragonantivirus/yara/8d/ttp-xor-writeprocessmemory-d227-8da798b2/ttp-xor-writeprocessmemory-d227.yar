rule TTP_XOR_WriteProcessMemory_d227 {
  strings:
    $key_d227 = { 85 55 [2] b7 77 [2] b1 42 [2] 9f 42 [2] a0 5e }

  condition:
    any of them
}