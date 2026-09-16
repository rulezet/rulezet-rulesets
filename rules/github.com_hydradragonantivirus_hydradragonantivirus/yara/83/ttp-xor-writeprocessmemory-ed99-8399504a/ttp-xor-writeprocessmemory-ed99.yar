rule TTP_XOR_WriteProcessMemory_ed99 {
  strings:
    $key_ed99 = { ba eb [2] 88 c9 [2] 8e fc [2] a0 fc [2] 9f e0 }

  condition:
    any of them
}