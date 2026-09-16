rule TTP_XOR_WriteProcessMemory_ef22 {
  strings:
    $key_ef22 = { b8 50 [2] 8a 72 [2] 8c 47 [2] a2 47 [2] 9d 5b }

  condition:
    any of them
}