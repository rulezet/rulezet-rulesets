rule TTP_XOR_WriteProcessMemory_f9cb {
  strings:
    $key_f9cb = { ae b9 [2] 9c 9b [2] 9a ae [2] b4 ae [2] 8b b2 }

  condition:
    any of them
}