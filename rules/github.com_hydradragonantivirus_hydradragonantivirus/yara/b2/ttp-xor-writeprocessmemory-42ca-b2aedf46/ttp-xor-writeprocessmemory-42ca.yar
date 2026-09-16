rule TTP_XOR_WriteProcessMemory_42ca {
  strings:
    $key_42ca = { 15 b8 [2] 27 9a [2] 21 af [2] 0f af [2] 30 b3 }

  condition:
    any of them
}