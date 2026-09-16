rule TTP_XOR_WriteProcessMemory_d51e {
  strings:
    $key_d51e = { 82 6c [2] b0 4e [2] b6 7b [2] 98 7b [2] a7 67 }

  condition:
    any of them
}