rule TTP_XOR_WriteProcessMemory_7099 {
  strings:
    $key_7099 = { 27 eb [2] 15 c9 [2] 13 fc [2] 3d fc [2] 02 e0 }

  condition:
    any of them
}