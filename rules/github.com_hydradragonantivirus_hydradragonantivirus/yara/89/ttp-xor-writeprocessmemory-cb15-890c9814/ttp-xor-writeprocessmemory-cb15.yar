rule TTP_XOR_WriteProcessMemory_cb15 {
  strings:
    $key_cb15 = { 9c 67 [2] ae 45 [2] a8 70 [2] 86 70 [2] b9 6c }

  condition:
    any of them
}