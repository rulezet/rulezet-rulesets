rule TTP_XOR_WriteProcessMemory_7e88 {
  strings:
    $key_7e88 = { 29 fa [2] 1b d8 [2] 1d ed [2] 33 ed [2] 0c f1 }

  condition:
    any of them
}