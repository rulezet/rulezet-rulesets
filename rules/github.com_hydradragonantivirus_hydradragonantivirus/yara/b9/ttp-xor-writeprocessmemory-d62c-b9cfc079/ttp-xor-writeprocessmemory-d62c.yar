rule TTP_XOR_WriteProcessMemory_d62c {
  strings:
    $key_d62c = { 81 5e [2] b3 7c [2] b5 49 [2] 9b 49 [2] a4 55 }

  condition:
    any of them
}