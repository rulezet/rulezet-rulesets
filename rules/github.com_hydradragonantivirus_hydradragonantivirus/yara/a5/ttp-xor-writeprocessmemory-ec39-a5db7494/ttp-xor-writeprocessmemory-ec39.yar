rule TTP_XOR_WriteProcessMemory_ec39 {
  strings:
    $key_ec39 = { bb 4b [2] 89 69 [2] 8f 5c [2] a1 5c [2] 9e 40 }

  condition:
    any of them
}