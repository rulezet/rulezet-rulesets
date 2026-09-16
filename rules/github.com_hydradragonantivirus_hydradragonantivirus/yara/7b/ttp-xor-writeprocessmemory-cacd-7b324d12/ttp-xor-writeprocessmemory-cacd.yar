rule TTP_XOR_WriteProcessMemory_cacd {
  strings:
    $key_cacd = { 9d bf [2] af 9d [2] a9 a8 [2] 87 a8 [2] b8 b4 }

  condition:
    any of them
}