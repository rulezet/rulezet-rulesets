rule TTP_XOR_WriteProcessMemory_2688 {
  strings:
    $key_2688 = { 71 fa [2] 43 d8 [2] 45 ed [2] 6b ed [2] 54 f1 }

  condition:
    any of them
}