rule TTP_XOR_WriteProcessMemory_24da {
  strings:
    $key_24da = { 73 a8 [2] 41 8a [2] 47 bf [2] 69 bf [2] 56 a3 }

  condition:
    any of them
}