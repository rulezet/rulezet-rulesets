rule TTP_XOR_WriteProcessMemory_d376 {
  strings:
    $key_d376 = { 84 04 [2] b6 26 [2] b0 13 [2] 9e 13 [2] a1 0f }

  condition:
    any of them
}