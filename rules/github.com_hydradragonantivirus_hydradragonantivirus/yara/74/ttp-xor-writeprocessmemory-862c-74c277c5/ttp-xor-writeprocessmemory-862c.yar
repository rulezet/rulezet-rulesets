rule TTP_XOR_WriteProcessMemory_862c {
  strings:
    $key_862c = { d1 5e [2] e3 7c [2] e5 49 [2] cb 49 [2] f4 55 }

  condition:
    any of them
}