rule TTP_XOR_WriteProcessMemory_eb35 {
  strings:
    $key_eb35 = { bc 47 [2] 8e 65 [2] 88 50 [2] a6 50 [2] 99 4c }

  condition:
    any of them
}