rule TTP_XOR_WriteProcessMemory_e3ef {
  strings:
    $key_e3ef = { b4 9d [2] 86 bf [2] 80 8a [2] ae 8a [2] 91 96 }

  condition:
    any of them
}