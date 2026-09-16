rule TTP_XOR_WriteProcessMemory_cb22 {
  strings:
    $key_cb22 = { 9c 50 [2] ae 72 [2] a8 47 [2] 86 47 [2] b9 5b }

  condition:
    any of them
}