rule TTP_XOR_WriteProcessMemory_d315 {
  strings:
    $key_d315 = { 84 67 [2] b6 45 [2] b0 70 [2] 9e 70 [2] a1 6c }

  condition:
    any of them
}