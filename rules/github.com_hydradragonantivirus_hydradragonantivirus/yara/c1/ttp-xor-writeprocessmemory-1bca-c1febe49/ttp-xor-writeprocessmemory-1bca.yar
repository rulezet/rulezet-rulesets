rule TTP_XOR_WriteProcessMemory_1bca {
  strings:
    $key_1bca = { 4c b8 [2] 7e 9a [2] 78 af [2] 56 af [2] 69 b3 }

  condition:
    any of them
}