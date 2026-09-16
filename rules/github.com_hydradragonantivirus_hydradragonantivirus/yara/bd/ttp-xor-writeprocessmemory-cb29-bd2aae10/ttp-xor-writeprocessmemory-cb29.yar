rule TTP_XOR_WriteProcessMemory_cb29 {
  strings:
    $key_cb29 = { 9c 5b [2] ae 79 [2] a8 4c [2] 86 4c [2] b9 50 }

  condition:
    any of them
}