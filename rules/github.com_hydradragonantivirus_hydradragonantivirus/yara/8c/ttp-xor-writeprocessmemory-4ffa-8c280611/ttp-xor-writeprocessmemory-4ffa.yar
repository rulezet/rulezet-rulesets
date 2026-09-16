rule TTP_XOR_WriteProcessMemory_4ffa {
  strings:
    $key_4ffa = { 18 88 [2] 2a aa [2] 2c 9f [2] 02 9f [2] 3d 83 }

  condition:
    any of them
}