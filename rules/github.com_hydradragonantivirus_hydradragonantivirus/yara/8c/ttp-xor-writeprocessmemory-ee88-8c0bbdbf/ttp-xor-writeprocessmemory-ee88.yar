rule TTP_XOR_WriteProcessMemory_ee88 {
  strings:
    $key_ee88 = { b9 fa [2] 8b d8 [2] 8d ed [2] a3 ed [2] 9c f1 }

  condition:
    any of them
}