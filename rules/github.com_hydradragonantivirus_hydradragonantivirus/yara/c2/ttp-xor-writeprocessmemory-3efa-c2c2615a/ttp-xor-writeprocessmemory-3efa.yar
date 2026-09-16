rule TTP_XOR_WriteProcessMemory_3efa {
  strings:
    $key_3efa = { 69 88 [2] 5b aa [2] 5d 9f [2] 73 9f [2] 4c 83 }

  condition:
    any of them
}