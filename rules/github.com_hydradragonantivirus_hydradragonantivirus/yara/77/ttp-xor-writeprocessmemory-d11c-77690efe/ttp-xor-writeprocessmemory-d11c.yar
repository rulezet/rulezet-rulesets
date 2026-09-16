rule TTP_XOR_WriteProcessMemory_d11c {
  strings:
    $key_d11c = { 86 6e [2] b4 4c [2] b2 79 [2] 9c 79 [2] a3 65 }

  condition:
    any of them
}