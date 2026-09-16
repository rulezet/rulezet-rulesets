rule TTP_XOR_WriteProcessMemory_31da {
  strings:
    $key_31da = { 66 a8 [2] 54 8a [2] 52 bf [2] 7c bf [2] 43 a3 }

  condition:
    any of them
}