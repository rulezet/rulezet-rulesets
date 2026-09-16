rule TTP_XOR_WriteProcessMemory_c377 {
  strings:
    $key_c377 = { 94 05 [2] a6 27 [2] a0 12 [2] 8e 12 [2] b1 0e }

  condition:
    any of them
}