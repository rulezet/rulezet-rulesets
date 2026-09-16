rule TTP_XOR_WriteProcessMemory_bcf8 {
  strings:
    $key_bcf8 = { eb 8a [2] d9 a8 [2] df 9d [2] f1 9d [2] ce 81 }

  condition:
    any of them
}