rule TTP_XOR_WriteProcessMemory_d133 {
  strings:
    $key_d133 = { 86 41 [2] b4 63 [2] b2 56 [2] 9c 56 [2] a3 4a }

  condition:
    any of them
}