rule TTP_XOR_WriteProcessMemory_c420 {
  strings:
    $key_c420 = { 93 52 [2] a1 70 [2] a7 45 [2] 89 45 [2] b6 59 }

  condition:
    any of them
}