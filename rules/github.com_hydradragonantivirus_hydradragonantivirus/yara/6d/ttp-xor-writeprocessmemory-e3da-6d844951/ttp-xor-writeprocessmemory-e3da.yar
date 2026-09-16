rule TTP_XOR_WriteProcessMemory_e3da {
  strings:
    $key_e3da = { b4 a8 [2] 86 8a [2] 80 bf [2] ae bf [2] 91 a3 }

  condition:
    any of them
}