rule TTP_XOR_WriteProcessMemory_3bef {
  strings:
    $key_3bef = { 6c 9d [2] 5e bf [2] 58 8a [2] 76 8a [2] 49 96 }

  condition:
    any of them
}