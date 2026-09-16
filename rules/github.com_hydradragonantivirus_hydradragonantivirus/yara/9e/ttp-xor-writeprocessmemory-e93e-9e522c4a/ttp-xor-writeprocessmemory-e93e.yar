rule TTP_XOR_WriteProcessMemory_e93e {
  strings:
    $key_e93e = { be 4c [2] 8c 6e [2] 8a 5b [2] a4 5b [2] 9b 47 }

  condition:
    any of them
}