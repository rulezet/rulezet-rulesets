rule TTP_XOR_WriteProcessMemory_0e88 {
  strings:
    $key_0e88 = { 59 fa [2] 6b d8 [2] 6d ed [2] 43 ed [2] 7c f1 }

  condition:
    any of them
}