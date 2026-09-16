rule TTP_XOR_WriteProcessMemory_d05c {
  strings:
    $key_d05c = { 87 2e [2] b5 0c [2] b3 39 [2] 9d 39 [2] a2 25 }

  condition:
    any of them
}