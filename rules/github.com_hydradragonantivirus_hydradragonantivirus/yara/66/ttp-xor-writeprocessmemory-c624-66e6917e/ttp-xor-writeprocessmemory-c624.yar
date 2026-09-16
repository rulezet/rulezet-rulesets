rule TTP_XOR_WriteProcessMemory_c624 {
  strings:
    $key_c624 = { 91 56 [2] a3 74 [2] a5 41 [2] 8b 41 [2] b4 5d }

  condition:
    any of them
}