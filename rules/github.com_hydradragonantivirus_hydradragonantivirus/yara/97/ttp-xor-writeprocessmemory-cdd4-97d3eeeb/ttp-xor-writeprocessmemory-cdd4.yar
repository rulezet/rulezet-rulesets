rule TTP_XOR_WriteProcessMemory_cdd4 {
  strings:
    $key_cdd4 = { 9a a6 [2] a8 84 [2] ae b1 [2] 80 b1 [2] bf ad }

  condition:
    any of them
}