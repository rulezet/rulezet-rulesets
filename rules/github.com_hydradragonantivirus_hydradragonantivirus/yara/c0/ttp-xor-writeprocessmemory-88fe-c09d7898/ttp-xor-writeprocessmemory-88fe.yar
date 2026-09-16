rule TTP_XOR_WriteProcessMemory_88fe {
  strings:
    $key_88fe = { df 8c [2] ed ae [2] eb 9b [2] c5 9b [2] fa 87 }

  condition:
    any of them
}