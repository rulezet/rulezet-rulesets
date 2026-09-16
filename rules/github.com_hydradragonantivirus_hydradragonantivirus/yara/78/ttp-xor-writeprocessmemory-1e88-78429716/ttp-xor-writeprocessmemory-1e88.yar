rule TTP_XOR_WriteProcessMemory_1e88 {
  strings:
    $key_1e88 = { 49 fa [2] 7b d8 [2] 7d ed [2] 53 ed [2] 6c f1 }

  condition:
    any of them
}