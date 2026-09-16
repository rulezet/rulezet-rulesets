rule TTP_XOR_WriteProcessMemory_d039 {
  strings:
    $key_d039 = { 87 4b [2] b5 69 [2] b3 5c [2] 9d 5c [2] a2 40 }

  condition:
    any of them
}