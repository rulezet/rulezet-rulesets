rule TTP_XOR_WriteProcessMemory_0fef {
  strings:
    $key_0fef = { 58 9d [2] 6a bf [2] 6c 8a [2] 42 8a [2] 7d 96 }

  condition:
    any of them
}