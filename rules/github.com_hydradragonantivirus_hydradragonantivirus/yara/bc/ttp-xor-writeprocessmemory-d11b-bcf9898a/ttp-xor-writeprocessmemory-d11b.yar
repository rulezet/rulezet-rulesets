rule TTP_XOR_WriteProcessMemory_d11b {
  strings:
    $key_d11b = { 86 69 [2] b4 4b [2] b2 7e [2] 9c 7e [2] a3 62 }

  condition:
    any of them
}