rule TTP_XOR_WriteProcessMemory_2988 {
  strings:
    $key_2988 = { 7e fa [2] 4c d8 [2] 4a ed [2] 64 ed [2] 5b f1 }

  condition:
    any of them
}