rule TTP_XOR_WriteProcessMemory_fe88 {
  strings:
    $key_fe88 = { a9 fa [2] 9b d8 [2] 9d ed [2] b3 ed [2] 8c f1 }

  condition:
    any of them
}