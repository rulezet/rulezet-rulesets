rule TTP_XOR_WriteProcessMemory_c649 {
  strings:
    $key_c649 = { 91 3b [2] a3 19 [2] a5 2c [2] 8b 2c [2] b4 30 }

  condition:
    any of them
}