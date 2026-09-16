rule TTP_XOR_WriteProcessMemory_8efe {
  strings:
    $key_8efe = { d9 8c [2] eb ae [2] ed 9b [2] c3 9b [2] fc 87 }

  condition:
    any of them
}