rule TTP_XOR_WriteProcessMemory_fa35 {
  strings:
    $key_fa35 = { ad 47 [2] 9f 65 [2] 99 50 [2] b7 50 [2] 88 4c }

  condition:
    any of them
}