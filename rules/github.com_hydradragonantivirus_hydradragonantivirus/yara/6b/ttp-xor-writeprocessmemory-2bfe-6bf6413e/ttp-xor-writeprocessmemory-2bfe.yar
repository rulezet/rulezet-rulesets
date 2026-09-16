rule TTP_XOR_WriteProcessMemory_2bfe {
  strings:
    $key_2bfe = { 7c 8c [2] 4e ae [2] 48 9b [2] 66 9b [2] 59 87 }

  condition:
    any of them
}