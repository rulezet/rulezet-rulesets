rule TTP_XOR_WriteProcessMemory_cb66 {
  strings:
    $key_cb66 = { 9c 14 [2] ae 36 [2] a8 03 [2] 86 03 [2] b9 1f }

  condition:
    any of them
}