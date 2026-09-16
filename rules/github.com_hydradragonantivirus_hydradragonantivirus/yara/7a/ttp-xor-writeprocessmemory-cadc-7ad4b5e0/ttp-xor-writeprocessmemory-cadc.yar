rule TTP_XOR_WriteProcessMemory_cadc {
  strings:
    $key_cadc = { 9d ae [2] af 8c [2] a9 b9 [2] 87 b9 [2] b8 a5 }

  condition:
    any of them
}