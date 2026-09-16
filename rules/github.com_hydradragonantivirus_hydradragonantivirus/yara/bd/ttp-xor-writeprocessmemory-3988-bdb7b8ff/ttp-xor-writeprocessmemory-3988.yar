rule TTP_XOR_WriteProcessMemory_3988 {
  strings:
    $key_3988 = { 6e fa [2] 5c d8 [2] 5a ed [2] 74 ed [2] 4b f1 }

  condition:
    any of them
}