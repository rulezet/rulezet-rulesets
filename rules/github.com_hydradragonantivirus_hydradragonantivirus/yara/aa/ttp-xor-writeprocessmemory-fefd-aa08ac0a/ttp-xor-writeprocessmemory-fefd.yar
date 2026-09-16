rule TTP_XOR_WriteProcessMemory_fefd {
  strings:
    $key_fefd = { a9 8f [2] 9b ad [2] 9d 98 [2] b3 98 [2] 8c 84 }

  condition:
    any of them
}