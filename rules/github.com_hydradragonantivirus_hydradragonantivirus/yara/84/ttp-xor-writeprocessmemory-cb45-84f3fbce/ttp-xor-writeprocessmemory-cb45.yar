rule TTP_XOR_WriteProcessMemory_cb45 {
  strings:
    $key_cb45 = { 9c 37 [2] ae 15 [2] a8 20 [2] 86 20 [2] b9 3c }

  condition:
    any of them
}