rule TTP_XOR_WriteProcessMemory_0afa {
  strings:
    $key_0afa = { 5d 88 [2] 6f aa [2] 69 9f [2] 47 9f [2] 78 83 }

  condition:
    any of them
}