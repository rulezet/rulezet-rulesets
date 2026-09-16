rule TTP_XOR_WriteProcessMemory_889d {
  strings:
    $key_889d = { df ef [2] ed cd [2] eb f8 [2] c5 f8 [2] fa e4 }

  condition:
    any of them
}