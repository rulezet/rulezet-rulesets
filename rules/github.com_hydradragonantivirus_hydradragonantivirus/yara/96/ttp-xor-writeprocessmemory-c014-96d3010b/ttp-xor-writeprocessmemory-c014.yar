rule TTP_XOR_WriteProcessMemory_c014 {
  strings:
    $key_c014 = { 97 66 [2] a5 44 [2] a3 71 [2] 8d 71 [2] b2 6d }

  condition:
    any of them
}