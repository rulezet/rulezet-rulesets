rule TTP_XOR_WriteProcessMemory_2b59 {
  strings:
    $key_2b59 = { 7c 2b [2] 4e 09 [2] 48 3c [2] 66 3c [2] 59 20 }

  condition:
    any of them
}