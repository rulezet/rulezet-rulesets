rule TTP_XOR_WriteProcessMemory_58ee {
  strings:
    $key_58ee = { 0f 9c [2] 3d be [2] 3b 8b [2] 15 8b [2] 2a 97 }

  condition:
    any of them
}