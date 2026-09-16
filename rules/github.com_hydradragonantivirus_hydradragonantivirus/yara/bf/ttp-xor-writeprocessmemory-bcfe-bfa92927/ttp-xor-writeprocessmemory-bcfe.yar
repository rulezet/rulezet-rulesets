rule TTP_XOR_WriteProcessMemory_bcfe {
  strings:
    $key_bcfe = { eb 8c [2] d9 ae [2] df 9b [2] f1 9b [2] ce 87 }

  condition:
    any of them
}