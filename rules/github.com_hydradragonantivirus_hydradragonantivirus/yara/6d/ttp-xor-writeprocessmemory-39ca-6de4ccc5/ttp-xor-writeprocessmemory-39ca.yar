rule TTP_XOR_WriteProcessMemory_39ca {
  strings:
    $key_39ca = { 6e b8 [2] 5c 9a [2] 5a af [2] 74 af [2] 4b b3 }

  condition:
    any of them
}