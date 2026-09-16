rule TTP_XOR_WriteProcessMemory_d019 {
  strings:
    $key_d019 = { 87 6b [2] b5 49 [2] b3 7c [2] 9d 7c [2] a2 60 }

  condition:
    any of them
}