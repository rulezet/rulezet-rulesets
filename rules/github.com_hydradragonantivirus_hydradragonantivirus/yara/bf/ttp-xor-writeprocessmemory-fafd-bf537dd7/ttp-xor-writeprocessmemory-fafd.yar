rule TTP_XOR_WriteProcessMemory_fafd {
  strings:
    $key_fafd = { ad 8f [2] 9f ad [2] 99 98 [2] b7 98 [2] 88 84 }

  condition:
    any of them
}