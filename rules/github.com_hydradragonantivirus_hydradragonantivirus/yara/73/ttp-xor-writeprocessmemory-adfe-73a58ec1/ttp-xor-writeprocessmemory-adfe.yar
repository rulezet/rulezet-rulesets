rule TTP_XOR_WriteProcessMemory_adfe {
  strings:
    $key_adfe = { fa 8c [2] c8 ae [2] ce 9b [2] e0 9b [2] df 87 }

  condition:
    any of them
}