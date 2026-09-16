rule TTP_XOR_WriteProcessMemory_0688 {
  strings:
    $key_0688 = { 51 fa [2] 63 d8 [2] 65 ed [2] 4b ed [2] 74 f1 }

  condition:
    any of them
}