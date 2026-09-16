rule TTP_XOR_WriteProcessMemory_a299 {
  strings:
    $key_a299 = { f5 eb [2] c7 c9 [2] c1 fc [2] ef fc [2] d0 e0 }

  condition:
    any of them
}