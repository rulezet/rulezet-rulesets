rule TTP_XOR_WriteProcessMemory_88ee {
  strings:
    $key_88ee = { df 9c [2] ed be [2] eb 8b [2] c5 8b [2] fa 97 }

  condition:
    any of them
}