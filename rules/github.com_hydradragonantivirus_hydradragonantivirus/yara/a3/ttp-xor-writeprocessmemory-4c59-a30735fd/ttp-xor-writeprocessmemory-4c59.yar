rule TTP_XOR_WriteProcessMemory_4c59 {
  strings:
    $key_4c59 = { 1b 2b [2] 29 09 [2] 2f 3c [2] 01 3c [2] 3e 20 }

  condition:
    any of them
}