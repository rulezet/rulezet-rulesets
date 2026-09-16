rule TTP_XOR_WriteProcessMemory_cddd {
  strings:
    $key_cddd = { 9a af [2] a8 8d [2] ae b8 [2] 80 b8 [2] bf a4 }

  condition:
    any of them
}