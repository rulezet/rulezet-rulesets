rule TTP_XOR_WriteProcessMemory_eab3 {
  strings:
    $key_eab3 = { bd c1 [2] 8f e3 [2] 89 d6 [2] a7 d6 [2] 98 ca }

  condition:
    any of them
}