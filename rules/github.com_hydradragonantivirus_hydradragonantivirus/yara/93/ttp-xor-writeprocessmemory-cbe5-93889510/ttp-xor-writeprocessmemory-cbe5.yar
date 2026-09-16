rule TTP_XOR_WriteProcessMemory_cbe5 {
  strings:
    $key_cbe5 = { 9c 97 [2] ae b5 [2] a8 80 [2] 86 80 [2] b9 9c }

  condition:
    any of them
}