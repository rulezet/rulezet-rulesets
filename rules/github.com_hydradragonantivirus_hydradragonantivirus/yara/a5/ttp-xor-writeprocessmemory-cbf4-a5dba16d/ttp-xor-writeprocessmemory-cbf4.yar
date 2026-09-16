rule TTP_XOR_WriteProcessMemory_cbf4 {
  strings:
    $key_cbf4 = { 9c 86 [2] ae a4 [2] a8 91 [2] 86 91 [2] b9 8d }

  condition:
    any of them
}