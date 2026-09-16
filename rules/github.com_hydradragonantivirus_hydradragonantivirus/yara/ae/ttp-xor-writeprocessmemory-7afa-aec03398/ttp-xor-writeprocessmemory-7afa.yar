rule TTP_XOR_WriteProcessMemory_7afa {
  strings:
    $key_7afa = { 2d 88 [2] 1f aa [2] 19 9f [2] 37 9f [2] 08 83 }

  condition:
    any of them
}