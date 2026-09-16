rule TTP_XOR_WriteProcessMemory_efda {
  strings:
    $key_efda = { b8 a8 [2] 8a 8a [2] 8c bf [2] a2 bf [2] 9d a3 }

  condition:
    any of them
}