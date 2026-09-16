rule TTP_XOR_WriteProcessMemory_cb35 {
  strings:
    $key_cb35 = { 9c 47 [2] ae 65 [2] a8 50 [2] 86 50 [2] b9 4c }

  condition:
    any of them
}