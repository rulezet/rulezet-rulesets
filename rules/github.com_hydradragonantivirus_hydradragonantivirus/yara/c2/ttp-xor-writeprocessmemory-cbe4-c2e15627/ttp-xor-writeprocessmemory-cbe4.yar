rule TTP_XOR_WriteProcessMemory_cbe4 {
  strings:
    $key_cbe4 = { 9c 96 [2] ae b4 [2] a8 81 [2] 86 81 [2] b9 9d }

  condition:
    any of them
}