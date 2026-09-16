rule TTP_XOR_WriteProcessMemory_c439 {
  strings:
    $key_c439 = { 93 4b [2] a1 69 [2] a7 5c [2] 89 5c [2] b6 40 }

  condition:
    any of them
}