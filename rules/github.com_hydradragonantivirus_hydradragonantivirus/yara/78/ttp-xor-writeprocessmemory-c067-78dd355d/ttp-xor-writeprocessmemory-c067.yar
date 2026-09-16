rule TTP_XOR_WriteProcessMemory_c067 {
  strings:
    $key_c067 = { 97 15 [2] a5 37 [2] a3 02 [2] 8d 02 [2] b2 1e }

  condition:
    any of them
}