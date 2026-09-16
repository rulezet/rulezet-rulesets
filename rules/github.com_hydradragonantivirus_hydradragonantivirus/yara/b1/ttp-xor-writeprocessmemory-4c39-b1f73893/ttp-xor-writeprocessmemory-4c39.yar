rule TTP_XOR_WriteProcessMemory_4c39 {
  strings:
    $key_4c39 = { 1b 4b [2] 29 69 [2] 2f 5c [2] 01 5c [2] 3e 40 }

  condition:
    any of them
}