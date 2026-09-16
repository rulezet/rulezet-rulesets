rule TTP_XOR_WriteProcessMemory_ec29 {
  strings:
    $key_ec29 = { bb 5b [2] 89 79 [2] 8f 4c [2] a1 4c [2] 9e 50 }

  condition:
    any of them
}