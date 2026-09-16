rule TTP_XOR_WriteProcessMemory_d31e {
  strings:
    $key_d31e = { 84 6c [2] b6 4e [2] b0 7b [2] 9e 7b [2] a1 67 }

  condition:
    any of them
}