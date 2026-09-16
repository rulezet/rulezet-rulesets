rule TTP_XOR_WriteProcessMemory_ec19 {
  strings:
    $key_ec19 = { bb 6b [2] 89 49 [2] 8f 7c [2] a1 7c [2] 9e 60 }

  condition:
    any of them
}