rule TTP_XOR_WriteProcessMemory_eeda {
  strings:
    $key_eeda = { b9 a8 [2] 8b 8a [2] 8d bf [2] a3 bf [2] 9c a3 }

  condition:
    any of them
}