rule TTP_XOR_WriteProcessMemory_cb34 {
  strings:
    $key_cb34 = { 9c 46 [2] ae 64 [2] a8 51 [2] 86 51 [2] b9 4d }

  condition:
    any of them
}