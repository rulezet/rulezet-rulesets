rule TTP_XOR_WriteProcessMemory_09da {
  strings:
    $key_09da = { 5e a8 [2] 6c 8a [2] 6a bf [2] 44 bf [2] 7b a3 }

  condition:
    any of them
}