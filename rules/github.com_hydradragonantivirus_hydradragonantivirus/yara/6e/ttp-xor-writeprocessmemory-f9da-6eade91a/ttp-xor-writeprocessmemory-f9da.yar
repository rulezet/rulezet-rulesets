rule TTP_XOR_WriteProcessMemory_f9da {
  strings:
    $key_f9da = { ae a8 [2] 9c 8a [2] 9a bf [2] b4 bf [2] 8b a3 }

  condition:
    any of them
}