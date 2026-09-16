rule TTP_XOR_WriteProcessMemory_cb25 {
  strings:
    $key_cb25 = { 9c 57 [2] ae 75 [2] a8 40 [2] 86 40 [2] b9 5c }

  condition:
    any of them
}