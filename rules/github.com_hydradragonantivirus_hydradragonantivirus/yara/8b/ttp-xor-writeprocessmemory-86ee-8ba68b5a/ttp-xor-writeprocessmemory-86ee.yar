rule TTP_XOR_WriteProcessMemory_86ee {
  strings:
    $key_86ee = { d1 9c [2] e3 be [2] e5 8b [2] cb 8b [2] f4 97 }

  condition:
    any of them
}