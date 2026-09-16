rule TTP_XOR_WriteProcessMemory_9087 {
  strings:
    $key_9087 = { c7 f5 [2] f5 d7 [2] f3 e2 [2] dd e2 [2] e2 fe }

  condition:
    any of them
}