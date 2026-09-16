rule TTP_XOR_WriteProcessMemory_c12c {
  strings:
    $key_c12c = { 96 5e [2] a4 7c [2] a2 49 [2] 8c 49 [2] b3 55 }

  condition:
    any of them
}