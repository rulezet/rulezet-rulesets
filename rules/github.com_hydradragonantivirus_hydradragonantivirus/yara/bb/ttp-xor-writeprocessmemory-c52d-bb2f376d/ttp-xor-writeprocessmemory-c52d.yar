rule TTP_XOR_WriteProcessMemory_c52d {
  strings:
    $key_c52d = { 92 5f [2] a0 7d [2] a6 48 [2] 88 48 [2] b7 54 }

  condition:
    any of them
}