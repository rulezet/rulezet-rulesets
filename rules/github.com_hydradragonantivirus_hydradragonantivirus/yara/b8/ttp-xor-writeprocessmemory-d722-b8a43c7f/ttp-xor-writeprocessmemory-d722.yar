rule TTP_XOR_WriteProcessMemory_d722 {
  strings:
    $key_d722 = { 80 50 [2] b2 72 [2] b4 47 [2] 9a 47 [2] a5 5b }

  condition:
    any of them
}