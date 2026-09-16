rule TTP_XOR_WriteProcessMemory_ef17 {
  strings:
    $key_ef17 = { b8 65 [2] 8a 47 [2] 8c 72 [2] a2 72 [2] 9d 6e }

  condition:
    any of them
}