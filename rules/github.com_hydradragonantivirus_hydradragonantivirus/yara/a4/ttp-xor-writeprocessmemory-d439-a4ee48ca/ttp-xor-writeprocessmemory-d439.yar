rule TTP_XOR_WriteProcessMemory_d439 {
  strings:
    $key_d439 = { 83 4b [2] b1 69 [2] b7 5c [2] 99 5c [2] a6 40 }

  condition:
    any of them
}