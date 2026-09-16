rule TTP_XOR_WriteProcessMemory_88ef {
  strings:
    $key_88ef = { df 9d [2] ed bf [2] eb 8a [2] c5 8a [2] fa 96 }

  condition:
    any of them
}