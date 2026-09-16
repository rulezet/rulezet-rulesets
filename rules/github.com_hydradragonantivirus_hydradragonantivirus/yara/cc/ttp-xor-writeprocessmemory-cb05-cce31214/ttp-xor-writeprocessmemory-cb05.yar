rule TTP_XOR_WriteProcessMemory_cb05 {
  strings:
    $key_cb05 = { 9c 77 [2] ae 55 [2] a8 60 [2] 86 60 [2] b9 7c }

  condition:
    any of them
}