rule TTP_XOR_WriteProcessMemory_e2ef {
  strings:
    $key_e2ef = { b5 9d [2] 87 bf [2] 81 8a [2] af 8a [2] 90 96 }

  condition:
    any of them
}