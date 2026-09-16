rule TTP_XOR_WriteProcessMemory_d782 {
  strings:
    $key_d782 = { 80 f0 [2] b2 d2 [2] b4 e7 [2] 9a e7 [2] a5 fb }

  condition:
    any of them
}