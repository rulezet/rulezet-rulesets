rule TTP_XOR_WriteProcessMemory_ddcb {
  strings:
    $key_ddcb = { 8a b9 [2] b8 9b [2] be ae [2] 90 ae [2] af b2 }

  condition:
    any of them
}