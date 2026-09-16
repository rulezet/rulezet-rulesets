rule TTP_XOR_WriteProcessMemory_bce3 {
  strings:
    $key_bce3 = { eb 91 [2] d9 b3 [2] df 86 [2] f1 86 [2] ce 9a }

  condition:
    any of them
}