rule TTP_XOR_WriteProcessMemory_caee {
  strings:
    $key_caee = { 9d 9c [2] af be [2] a9 8b [2] 87 8b [2] b8 97 }

  condition:
    any of them
}