rule TTP_XOR_WriteProcessMemory_4bca {
  strings:
    $key_4bca = { 1c b8 [2] 2e 9a [2] 28 af [2] 06 af [2] 39 b3 }

  condition:
    any of them
}