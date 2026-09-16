rule TTP_XOR_WriteProcessMemory_dad5 {
  strings:
    $key_dad5 = { 8d a7 [2] bf 85 [2] b9 b0 [2] 97 b0 [2] a8 ac }

  condition:
    any of them
}