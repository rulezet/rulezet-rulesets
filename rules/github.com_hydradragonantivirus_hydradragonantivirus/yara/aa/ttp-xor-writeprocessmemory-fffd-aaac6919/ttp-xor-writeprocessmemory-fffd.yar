rule TTP_XOR_WriteProcessMemory_fffd {
  strings:
    $key_fffd = { a8 8f [2] 9a ad [2] 9c 98 [2] b2 98 [2] 8d 84 }

  condition:
    any of them
}