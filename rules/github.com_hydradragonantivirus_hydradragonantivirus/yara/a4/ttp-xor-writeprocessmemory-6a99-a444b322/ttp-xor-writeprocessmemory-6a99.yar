rule TTP_XOR_WriteProcessMemory_6a99 {
  strings:
    $key_6a99 = { 3d eb [2] 0f c9 [2] 09 fc [2] 27 fc [2] 18 e0 }

  condition:
    any of them
}