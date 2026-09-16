rule TTP_XOR_WriteProcessMemory_88df {
  strings:
    $key_88df = { df ad [2] ed 8f [2] eb ba [2] c5 ba [2] fa a6 }

  condition:
    any of them
}