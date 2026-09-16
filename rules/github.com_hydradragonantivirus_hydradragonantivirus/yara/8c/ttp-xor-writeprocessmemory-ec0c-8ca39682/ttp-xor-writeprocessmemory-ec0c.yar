rule TTP_XOR_WriteProcessMemory_ec0c {
  strings:
    $key_ec0c = { bb 7e [2] 89 5c [2] 8f 69 [2] a1 69 [2] 9e 75 }

  condition:
    any of them
}