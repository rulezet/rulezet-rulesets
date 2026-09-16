rule TTP_XOR_WriteProcessMemory_ca29 {
  strings:
    $key_ca29 = { 9d 5b [2] af 79 [2] a9 4c [2] 87 4c [2] b8 50 }

  condition:
    any of them
}