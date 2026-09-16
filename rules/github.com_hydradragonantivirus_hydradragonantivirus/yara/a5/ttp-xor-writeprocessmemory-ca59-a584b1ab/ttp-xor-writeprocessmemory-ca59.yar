rule TTP_XOR_WriteProcessMemory_ca59 {
  strings:
    $key_ca59 = { 9d 2b [2] af 09 [2] a9 3c [2] 87 3c [2] b8 20 }

  condition:
    any of them
}