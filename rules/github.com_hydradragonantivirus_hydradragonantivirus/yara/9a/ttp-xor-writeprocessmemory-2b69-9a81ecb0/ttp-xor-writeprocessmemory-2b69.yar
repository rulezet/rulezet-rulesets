rule TTP_XOR_WriteProcessMemory_2b69 {
  strings:
    $key_2b69 = { 7c 1b [2] 4e 39 [2] 48 0c [2] 66 0c [2] 59 10 }

  condition:
    any of them
}