rule TTP_XOR_WriteProcessMemory_d03c {
  strings:
    $key_d03c = { 87 4e [2] b5 6c [2] b3 59 [2] 9d 59 [2] a2 45 }

  condition:
    any of them
}