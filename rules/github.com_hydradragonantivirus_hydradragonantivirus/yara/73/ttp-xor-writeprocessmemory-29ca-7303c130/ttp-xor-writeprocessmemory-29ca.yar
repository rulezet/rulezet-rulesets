rule TTP_XOR_WriteProcessMemory_29ca {
  strings:
    $key_29ca = { 7e b8 [2] 4c 9a [2] 4a af [2] 64 af [2] 5b b3 }

  condition:
    any of them
}