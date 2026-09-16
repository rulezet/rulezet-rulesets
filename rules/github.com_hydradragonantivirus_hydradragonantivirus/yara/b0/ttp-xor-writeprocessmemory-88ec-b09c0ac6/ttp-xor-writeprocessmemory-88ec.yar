rule TTP_XOR_WriteProcessMemory_88ec {
  strings:
    $key_88ec = { df 9e [2] ed bc [2] eb 89 [2] c5 89 [2] fa 95 }

  condition:
    any of them
}