rule TTP_XOR_WriteProcessMemory_cabe {
  strings:
    $key_cabe = { 9d cc [2] af ee [2] a9 db [2] 87 db [2] b8 c7 }

  condition:
    any of them
}