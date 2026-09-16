rule TTP_XOR_WriteProcessMemory_cbcb {
  strings:
    $key_cbcb = { 9c b9 [2] ae 9b [2] a8 ae [2] 86 ae [2] b9 b2 }

  condition:
    any of them
}