rule TTP_XOR_WriteProcessMemory_ef27 {
  strings:
    $key_ef27 = { b8 55 [2] 8a 77 [2] 8c 42 [2] a2 42 [2] 9d 5e }

  condition:
    any of them
}