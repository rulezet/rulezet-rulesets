rule TTP_XOR_WriteProcessMemory_3699 {
  strings:
    $key_3699 = { 61 eb [2] 53 c9 [2] 55 fc [2] 7b fc [2] 44 e0 }

  condition:
    any of them
}