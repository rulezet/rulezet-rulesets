rule TTP_XOR_WriteProcessMemory_cb14 {
  strings:
    $key_cb14 = { 9c 66 [2] ae 44 [2] a8 71 [2] 86 71 [2] b9 6d }

  condition:
    any of them
}