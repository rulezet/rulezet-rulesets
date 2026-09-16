rule TTP_XOR_WriteProcessMemory_089a {
  strings:
    $key_089a = { 5f e8 [2] 6d ca [2] 6b ff [2] 45 ff [2] 7a e3 }

  condition:
    any of them
}