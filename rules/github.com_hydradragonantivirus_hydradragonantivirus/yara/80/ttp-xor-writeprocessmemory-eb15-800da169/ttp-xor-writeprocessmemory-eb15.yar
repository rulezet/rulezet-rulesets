rule TTP_XOR_WriteProcessMemory_eb15 {
  strings:
    $key_eb15 = { bc 67 [2] 8e 45 [2] 88 70 [2] a6 70 [2] 99 6c }

  condition:
    any of them
}