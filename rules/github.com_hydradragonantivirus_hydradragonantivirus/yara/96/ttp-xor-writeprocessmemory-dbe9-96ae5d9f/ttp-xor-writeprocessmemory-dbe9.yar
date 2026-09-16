rule TTP_XOR_WriteProcessMemory_dbe9 {
  strings:
    $key_dbe9 = { 8c 9b [2] be b9 [2] b8 8c [2] 96 8c [2] a9 90 }

  condition:
    any of them
}