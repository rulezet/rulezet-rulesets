rule TTP_XOR_WriteProcessMemory_cb59 {
  strings:
    $key_cb59 = { 9c 2b [2] ae 09 [2] a8 3c [2] 86 3c [2] b9 20 }

  condition:
    any of them
}