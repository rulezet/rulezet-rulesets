rule TTP_XOR_WriteProcessMemory_cb54 {
  strings:
    $key_cb54 = { 9c 26 [2] ae 04 [2] a8 31 [2] 86 31 [2] b9 2d }

  condition:
    any of them
}