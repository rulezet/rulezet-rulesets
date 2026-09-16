rule TTP_XOR_WriteProcessMemory_88cc {
  strings:
    $key_88cc = { df be [2] ed 9c [2] eb a9 [2] c5 a9 [2] fa b5 }

  condition:
    any of them
}