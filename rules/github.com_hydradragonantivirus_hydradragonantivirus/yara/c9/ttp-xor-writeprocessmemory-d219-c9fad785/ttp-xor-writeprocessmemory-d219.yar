rule TTP_XOR_WriteProcessMemory_d219 {
  strings:
    $key_d219 = { 85 6b [2] b7 49 [2] b1 7c [2] 9f 7c [2] a0 60 }

  condition:
    any of them
}