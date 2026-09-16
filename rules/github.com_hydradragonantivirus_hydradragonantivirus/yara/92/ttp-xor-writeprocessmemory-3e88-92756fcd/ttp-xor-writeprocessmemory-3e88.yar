rule TTP_XOR_WriteProcessMemory_3e88 {
  strings:
    $key_3e88 = { 69 fa [2] 5b d8 [2] 5d ed [2] 73 ed [2] 4c f1 }

  condition:
    any of them
}