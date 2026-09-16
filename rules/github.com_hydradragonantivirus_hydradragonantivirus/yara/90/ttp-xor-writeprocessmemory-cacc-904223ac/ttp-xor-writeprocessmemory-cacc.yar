rule TTP_XOR_WriteProcessMemory_cacc {
  strings:
    $key_cacc = { 9d be [2] af 9c [2] a9 a9 [2] 87 a9 [2] b8 b5 }

  condition:
    any of them
}