rule TTP_XOR_WriteProcessMemory_bcfd {
  strings:
    $key_bcfd = { eb 8f [2] d9 ad [2] df 98 [2] f1 98 [2] ce 84 }

  condition:
    any of them
}