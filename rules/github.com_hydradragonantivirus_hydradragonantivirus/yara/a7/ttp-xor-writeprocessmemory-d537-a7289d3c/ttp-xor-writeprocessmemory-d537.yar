rule TTP_XOR_WriteProcessMemory_d537 {
  strings:
    $key_d537 = { 82 45 [2] b0 67 [2] b6 52 [2] 98 52 [2] a7 4e }

  condition:
    any of them
}