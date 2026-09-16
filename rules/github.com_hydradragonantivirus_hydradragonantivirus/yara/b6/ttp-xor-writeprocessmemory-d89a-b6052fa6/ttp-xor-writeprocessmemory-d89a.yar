rule TTP_XOR_WriteProcessMemory_d89a {
  strings:
    $key_d89a = { 8f e8 [2] bd ca [2] bb ff [2] 95 ff [2] aa e3 }

  condition:
    any of them
}