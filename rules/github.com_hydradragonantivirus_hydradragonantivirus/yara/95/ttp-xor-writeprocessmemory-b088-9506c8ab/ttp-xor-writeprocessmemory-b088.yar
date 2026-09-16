rule TTP_XOR_WriteProcessMemory_b088 {
  strings:
    $key_b088 = { e7 fa [2] d5 d8 [2] d3 ed [2] fd ed [2] c2 f1 }

  condition:
    any of them
}