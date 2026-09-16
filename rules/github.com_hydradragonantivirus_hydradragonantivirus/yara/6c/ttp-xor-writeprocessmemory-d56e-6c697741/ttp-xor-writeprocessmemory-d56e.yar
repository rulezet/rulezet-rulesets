rule TTP_XOR_WriteProcessMemory_d56e {
  strings:
    $key_d56e = { 82 1c [2] b0 3e [2] b6 0b [2] 98 0b [2] a7 17 }

  condition:
    any of them
}