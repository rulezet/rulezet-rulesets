rule TTP_XOR_WriteProcessMemory_3efe {
  strings:
    $key_3efe = { 69 8c [2] 5b ae [2] 5d 9b [2] 73 9b [2] 4c 87 }

  condition:
    any of them
}