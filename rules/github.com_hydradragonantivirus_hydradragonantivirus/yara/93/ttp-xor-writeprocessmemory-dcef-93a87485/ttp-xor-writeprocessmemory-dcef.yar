rule TTP_XOR_WriteProcessMemory_dcef {
  strings:
    $key_dcef = { 8b 9d [2] b9 bf [2] bf 8a [2] 91 8a [2] ae 96 }

  condition:
    any of them
}