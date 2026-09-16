rule TTP_XOR_WriteProcessMemory_1fef {
  strings:
    $key_1fef = { 48 9d [2] 7a bf [2] 7c 8a [2] 52 8a [2] 6d 96 }

  condition:
    any of them
}