rule TTP_XOR_WriteProcessMemory_2ab5 {
  strings:
    $key_2ab5 = { 7d c7 [2] 4f e5 [2] 49 d0 [2] 67 d0 [2] 58 cc }

  condition:
    any of them
}