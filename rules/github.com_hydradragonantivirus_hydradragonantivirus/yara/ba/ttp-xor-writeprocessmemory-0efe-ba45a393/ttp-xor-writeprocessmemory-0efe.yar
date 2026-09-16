rule TTP_XOR_WriteProcessMemory_0efe {
  strings:
    $key_0efe = { 59 8c [2] 6b ae [2] 6d 9b [2] 43 9b [2] 7c 87 }

  condition:
    any of them
}