rule TTP_XOR_WriteProcessMemory_5e88 {
  strings:
    $key_5e88 = { 09 fa [2] 3b d8 [2] 3d ed [2] 13 ed [2] 2c f1 }

  condition:
    any of them
}