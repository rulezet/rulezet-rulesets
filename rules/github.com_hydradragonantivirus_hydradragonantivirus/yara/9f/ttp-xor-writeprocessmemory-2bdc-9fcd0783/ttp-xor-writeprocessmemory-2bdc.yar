rule TTP_XOR_WriteProcessMemory_2bdc {
  strings:
    $key_2bdc = { 7c ae [2] 4e 8c [2] 48 b9 [2] 66 b9 [2] 59 a5 }

  condition:
    any of them
}