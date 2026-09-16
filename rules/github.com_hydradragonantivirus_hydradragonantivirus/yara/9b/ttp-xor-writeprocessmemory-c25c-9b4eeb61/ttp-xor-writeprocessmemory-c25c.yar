rule TTP_XOR_WriteProcessMemory_c25c {
  strings:
    $key_c25c = { 95 2e [2] a7 0c [2] a1 39 [2] 8f 39 [2] b0 25 }

  condition:
    any of them
}