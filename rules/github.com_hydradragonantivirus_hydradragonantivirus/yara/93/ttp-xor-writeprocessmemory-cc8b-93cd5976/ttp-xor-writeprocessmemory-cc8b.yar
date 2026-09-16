rule TTP_XOR_WriteProcessMemory_cc8b {
  strings:
    $key_cc8b = { 9b f9 [2] a9 db [2] af ee [2] 81 ee [2] be f2 }

  condition:
    any of them
}