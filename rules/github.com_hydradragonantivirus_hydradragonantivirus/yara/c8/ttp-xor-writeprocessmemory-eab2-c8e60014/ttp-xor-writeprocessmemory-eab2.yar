rule TTP_XOR_WriteProcessMemory_eab2 {
  strings:
    $key_eab2 = { bd c0 [2] 8f e2 [2] 89 d7 [2] a7 d7 [2] 98 cb }

  condition:
    any of them
}