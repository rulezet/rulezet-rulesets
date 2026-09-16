rule TTP_XOR_WriteProcessMemory_ab88 {
  strings:
    $key_ab88 = { fc fa [2] ce d8 [2] c8 ed [2] e6 ed [2] d9 f1 }

  condition:
    any of them
}