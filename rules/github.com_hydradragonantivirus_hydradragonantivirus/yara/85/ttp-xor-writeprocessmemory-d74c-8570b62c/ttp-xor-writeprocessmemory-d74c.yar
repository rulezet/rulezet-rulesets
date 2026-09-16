rule TTP_XOR_WriteProcessMemory_d74c {
  strings:
    $key_d74c = { 80 3e [2] b2 1c [2] b4 29 [2] 9a 29 [2] a5 35 }

  condition:
    any of them
}