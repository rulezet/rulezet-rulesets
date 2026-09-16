rule TTP_XOR_WriteProcessMemory_29da {
  strings:
    $key_29da = { 7e a8 [2] 4c 8a [2] 4a bf [2] 64 bf [2] 5b a3 }

  condition:
    any of them
}