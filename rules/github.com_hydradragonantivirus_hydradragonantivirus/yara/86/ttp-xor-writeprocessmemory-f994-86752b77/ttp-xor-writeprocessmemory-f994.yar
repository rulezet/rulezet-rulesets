rule TTP_XOR_WriteProcessMemory_f994 {
  strings:
    $key_f994 = { ae e6 [2] 9c c4 [2] 9a f1 [2] b4 f1 [2] 8b ed }

  condition:
    any of them
}