rule TTP_XOR_WriteProcessMemory_9487 {
  strings:
    $key_9487 = { c3 f5 [2] f1 d7 [2] f7 e2 [2] d9 e2 [2] e6 fe }

  condition:
    any of them
}