rule TTP_XOR_WriteProcessMemory_cb19 {
  strings:
    $key_cb19 = { 9c 6b [2] ae 49 [2] a8 7c [2] 86 7c [2] b9 60 }

  condition:
    any of them
}