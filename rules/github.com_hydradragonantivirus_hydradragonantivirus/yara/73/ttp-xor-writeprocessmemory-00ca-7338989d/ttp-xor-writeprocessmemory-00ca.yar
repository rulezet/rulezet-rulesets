rule TTP_XOR_WriteProcessMemory_00ca {
  strings:
    $key_00ca = { 57 b8 [2] 65 9a [2] 63 af [2] 4d af [2] 72 b3 }

  condition:
    any of them
}