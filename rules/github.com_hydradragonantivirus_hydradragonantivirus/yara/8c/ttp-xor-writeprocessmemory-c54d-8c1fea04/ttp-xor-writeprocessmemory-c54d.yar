rule TTP_XOR_WriteProcessMemory_c54d {
  strings:
    $key_c54d = { 92 3f [2] a0 1d [2] a6 28 [2] 88 28 [2] b7 34 }

  condition:
    any of them
}