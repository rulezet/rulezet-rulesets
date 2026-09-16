rule TTP_XOR_WriteProcessMemory_a1ab {
  strings:
    $key_a1ab = { f6 d9 [2] c4 fb [2] c2 ce [2] ec ce [2] d3 d2 }

  condition:
    any of them
}