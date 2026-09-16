rule TTP_XOR_WriteProcessMemory_d02b {
  strings:
    $key_d02b = { 87 59 [2] b5 7b [2] b3 4e [2] 9d 4e [2] a2 52 }

  condition:
    any of them
}