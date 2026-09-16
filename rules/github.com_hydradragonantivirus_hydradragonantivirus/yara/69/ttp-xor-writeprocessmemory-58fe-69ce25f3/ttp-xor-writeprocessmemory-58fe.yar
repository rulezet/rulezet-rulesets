rule TTP_XOR_WriteProcessMemory_58fe {
  strings:
    $key_58fe = { 0f 8c [2] 3d ae [2] 3b 9b [2] 15 9b [2] 2a 87 }

  condition:
    any of them
}