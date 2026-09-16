rule TTP_XOR_WriteProcessMemory_8e18 {
  strings:
    $key_8e18 = { d9 6a [2] eb 48 [2] ed 7d [2] c3 7d [2] fc 61 }

  condition:
    any of them
}