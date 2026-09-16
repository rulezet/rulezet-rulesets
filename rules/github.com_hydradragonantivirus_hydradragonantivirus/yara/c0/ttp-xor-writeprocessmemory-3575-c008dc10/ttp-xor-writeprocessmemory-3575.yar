rule TTP_XOR_WriteProcessMemory_3575 {
  strings:
    $key_3575 = { 62 07 [2] 50 25 [2] 56 10 [2] 78 10 [2] 47 0c }

  condition:
    any of them
}