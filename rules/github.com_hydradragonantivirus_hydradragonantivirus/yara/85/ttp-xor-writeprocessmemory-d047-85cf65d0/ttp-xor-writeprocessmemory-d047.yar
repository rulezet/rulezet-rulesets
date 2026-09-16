rule TTP_XOR_WriteProcessMemory_d047 {
  strings:
    $key_d047 = { 87 35 [2] b5 17 [2] b3 22 [2] 9d 22 [2] a2 3e }

  condition:
    any of them
}