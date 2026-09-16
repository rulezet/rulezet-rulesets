rule TTP_XOR_WriteProcessMemory_2b39 {
  strings:
    $key_2b39 = { 7c 4b [2] 4e 69 [2] 48 5c [2] 66 5c [2] 59 40 }

  condition:
    any of them
}