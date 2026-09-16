rule TTP_XOR_WriteProcessMemory_cb09 {
  strings:
    $key_cb09 = { 9c 7b [2] ae 59 [2] a8 6c [2] 86 6c [2] b9 70 }

  condition:
    any of them
}