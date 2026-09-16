rule TTP_XOR_WriteProcessMemory_d62d {
  strings:
    $key_d62d = { 81 5f [2] b3 7d [2] b5 48 [2] 9b 48 [2] a4 54 }

  condition:
    any of them
}