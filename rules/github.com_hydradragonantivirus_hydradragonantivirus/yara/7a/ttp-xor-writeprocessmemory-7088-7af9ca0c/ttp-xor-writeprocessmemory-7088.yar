rule TTP_XOR_WriteProcessMemory_7088 {
  strings:
    $key_7088 = { 27 fa [2] 15 d8 [2] 13 ed [2] 3d ed [2] 02 f1 }

  condition:
    any of them
}